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
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";

dotenv.config();
const port = process.env.PORT || 3000;
const redis = new Redis(`${process.env.PRIVATE_REDIS_URL}`, {
  maxRetriesPerRequest: null,
});
const createQueueMQ = (name: string) => new QueueMQ(name, { connection: redis });

const rateLimiter = (limit: number, window: number) => {
  return async (c: Context, next: () => Promise<void>) => {
    const ip = c.req.header("x-forwarded-for") || "unknown";
    const key = `bull-board:rate_limit:${ip}`;
    const current = await redis.incr(key);
    if (current === 1) {
      await redis.expire(key, window);
    }
    if (current > limit) {
      return c.text("Too many requests", 429);
    }
    await next();
  };
};

const SESSION_DURATION = 60 * 60 * 24 * 7; // 7 days in seconds

const refreshSession = async (c: Context, sessionToken: string) => {
  await redis.expire(`bull-board:session:${sessionToken}`, SESSION_DURATION);
  setCookie(c, "bullMqAdminSessionToken", sessionToken, {
    httpOnly: true,
    path: "/",
    maxAge: SESSION_DURATION,
    secure: process.env.ENV === "production",
    sameSite: "Lax",
  });
};

const QUEUE_PREFIX = process.env.QUEUE_PREFIX || "";
const PRIVATE_MANUAL_QUEUE_NAMES = process.env.PRIVATE_MANUAL_QUEUE_NAMES?.split(",").filter(Boolean) || [];

let discoveredQueues: BullMQAdapter[] = [];

const discoverQueues = async (): Promise<void> => {
  if (PRIVATE_MANUAL_QUEUE_NAMES.length > 0) {
    // Use only manually specified queues
    discoveredQueues = PRIVATE_MANUAL_QUEUE_NAMES.map((name) => {
      const queue = createQueueMQ(name);
      return new BullMQAdapter(queue);
    });
  } else {
    // Auto-discover queues
    const queueNames = new Set<string>();
    let cursor = "0";
    do {
      const [newCursor, keys] = await redis.scan(cursor, "MATCH", `bull:${QUEUE_PREFIX}*:meta`, "COUNT", "100");
      cursor = newCursor;
      keys.forEach((key) => queueNames.add(key.split(":")[1]));
    } while (cursor !== "0");

    discoveredQueues = Array.from(queueNames).map((name) => {
      const queue = createQueueMQ(name);
      return new BullMQAdapter(queue);
    });
  }
};

const run = async () => {
  const app = new Hono();

  const serverAdapter = new HonoAdapter(serveStatic);

  // Discover queues on startup
  await discoverQueues();

  createBullBoard({
    queues: discoveredQueues,
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
    const isValid = await redis.get(`bull-board:session:${sessionToken}`);
    if (!isValid) {
      return c.redirect("/login");
    }
    await refreshSession(c, sessionToken);
    await next();
  };

  // Apply auth middleware to /admin and all its subroutes
  app.use(`${basePath}/*`, authMiddleware);
  app.use(basePath, authMiddleware);

  // Register the Bull Board routes
  app.route(basePath, serverAdapter.registerPlugin());
  app.route(basePath + "/", serverAdapter.registerPlugin());

  // Redirect root route to /admin
  app.get("/", (c) => {
    return c.redirect(basePath);
  });

  // Login page
  app.get("/login", (c) => {
    return c.html(`
      <!DOCTYPE html>
      <html>
        <head>
          <style>
            * {
              margin: 0;
              padding: 0;
              box-sizing: border-box;
            }
            body {
              display: flex;
              justify-content: center;
              align-items: center;
              min-height: 100vh;
            }
            form {
              border: 1px solid;
              padding: 2rem;
              width: 300px;
            }
            input {
              width: 100%;
              padding: 0.5rem;
              margin-bottom: 1rem;
              border: 1px solid;
            }
            button {
              width: 100%;
              padding: 0.5rem;
              border: 1px solid;
              cursor: pointer;
            }
          </style>
        </head>
        <body>
          <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
          </form>
        </body>
      </html>
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
      storedHash &&
      bcrypt.compareSync(password.toString(), storedHash)
    ) {
      const sessionToken = uuidv4();
      await redis.set(`bull-board:session:${sessionToken}`, "valid", "EX", SESSION_DURATION);
      setCookie(c, "bullMqAdminSessionToken", sessionToken, {
        httpOnly: true,
        path: "/",
        maxAge: SESSION_DURATION,
        secure: process.env.ENV === "production",
        sameSite: "Lax",
      });
      return c.redirect(basePath);
    } else {
      return c.text("Invalid credentials", 401);
    }
  });

  // Logout route
  app.get("/logout", async (c) => {
    const sessionToken = getCookie(c, "bullMqAdminSessionToken");
    if (sessionToken) {
      await redis.del(`bull-board:session:${sessionToken}`);
    }
    setCookie(c, "bullMqAdminSessionToken", "", {
      httpOnly: true,
      path: "/",
      maxAge: 0,
    });
    return c.redirect("/login");
  });

  // Add a new route to trigger queue rediscovery
  app.get("/discoverQueues", authMiddleware, async (c) => {
    await discoverQueues();
    return c.json({
      message:
        PRIVATE_MANUAL_QUEUE_NAMES.length > 0
          ? "Using manually specified queues"
          : "Queues rediscovered successfully",
      count: discoveredQueues.length,
    });
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
