import { createBullBoard } from "@bull-board/api";
import { BullMQAdapter } from "@bull-board/api/bullMQAdapter";
import { HonoAdapter } from "@bull-board/hono";
import { Queue as QueueMQ } from "bullmq";
import { Context, Hono } from "hono";
import { showRoutes } from "hono/dev";
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Redis } from "ioredis";
import dotenv from "dotenv";
import { getCookie, setCookie } from "hono/cookie";
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

dotenv.config();
const port = process.env.PORT || 3000;
const redis = new Redis(`${process.env.PRIVATE_REDIS_URL}?family=0`, {
  maxRetriesPerRequest: null,
});
const createQueueMQ = (name: string) =>
  new QueueMQ(name, { connection: redis });

const rateLimiter = (limit: number, window: number) => {
  return async (c: Context, next: () => Promise<void>) => {
    const ip = c.req.header('x-forwarded-for') || 'unknown';
    const key = `bullmq:admin:rate_limit:${ip}`;
    const current = await redis.incr(key);
    if (current === 1) {
      await redis.expire(key, window);
    }
    if (current > limit) {
      return c.text('Too many requests', 429);
    }
    await next();
  };
};

const run = async () => {
  const app = new Hono();

  const serverAdapter = new HonoAdapter(serveStatic);
  const queueNames = process.env.PRIVATE_QUEUE_NAMES?.split(",") ?? [];
  const queues: BullMQAdapter[] = [];
  for (const name of queueNames) {
    const queue = createQueueMQ(name);
    queues.push(new BullMQAdapter(queue));
  }

  createBullBoard({
    queues,
    serverAdapter,
  });

  const basePath = "/admin";
  serverAdapter.setBasePath(basePath);

  // Middleware to check if user is authenticated
  const authMiddleware = async (c: Context<any, any, {}>, next: () => any) => {
    const sessionToken = getCookie(c, "bullMqAdminSessionToken");
    if (!sessionToken) {
      return c.redirect("/login");
    }
    const isValid = await redis.get(`bullmq:admin:session:${sessionToken}`);
    if (!isValid) {
      return c.redirect("/login");
    }
    await next();
  };

  // Apply auth middleware to /admin and all its subroutes
  app.use(`${basePath}/*`, authMiddleware);
  app.use(basePath, authMiddleware);

  // Register the Bull Board routes
  app.route(basePath, serverAdapter.registerPlugin());

  // Login page
  app.get("/login", (c) => {
    return c.html(`
      <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <button type="submit">Login</button>
      </form>
    `);
  });

  // Replace the loginRateLimiter definition with this:
  const loginRateLimiter = rateLimiter(5, 60); // 5 requests per 60 seconds

  // Login handler
  app.post("/login", loginRateLimiter, async (c) => {
    const { username, password } = await c.req.parseBody();
    const storedHash = process.env.PRIVATE_ADMIN_PASSWORD_HASH;
    
    if (
      username === process.env.PRIVATE_ADMIN_USERNAME &&
      storedHash && bcrypt.compareSync(password.toString(), storedHash)
    ) {
      const sessionToken = uuidv4();
      await redis.set(`bullmq:admin:session:${sessionToken}`, 'valid', 'EX', 60 * 60 * 24); // Expires in 24 hours
      setCookie(c, "bullMqAdminSessionToken", sessionToken, {
        httpOnly: true,
        path: "/",
        maxAge: 60 * 60 * 24, // 1 day
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Lax',
      });
      return c.redirect(basePath);
    } else {
      return c.text("Invalid credentials", 401);
    }
  });

  // Logout route
  app.get("/logout", async (c) => {
    const sessionToken = getCookie(c, "sessionToken");
    if (sessionToken) {
      await redis.del(`session:${sessionToken}`);
    }
    setCookie(c, "sessionToken", "", {
      httpOnly: true,
      path: "/",
      maxAge: 0,
    });
    return c.redirect("/login");
  });

  showRoutes(app);

  serve({ fetch: app.fetch, port: Number(port) }, ({ address, port }) => {
    console.log(`Running on ${address}:${port}...`);
  });
};

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
