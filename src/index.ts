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

dotenv.config();

const redis = new Redis(`${process.env.PRIVATE_REDIS_URL}?family=0`, {
  maxRetriesPerRequest: null,
});
const createQueueMQ = (name: string) =>
  new QueueMQ(name, { connection: redis });

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
    const isAuthenticated = getCookie(c, "isAuthenticated") === "true";
    if (!isAuthenticated) {
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

  // Login handler
  app.post("/login", async (c) => {
    const { username, password } = await c.req.parseBody();
    if (
      username === process.env.PRIVATE_ADMIN_USERNAME &&
      password === process.env.PRIVATE_ADMIN_PASSWORD
    ) {
      setCookie(c, "isAuthenticated", "true", {
        httpOnly: true,
        path: "/",
        maxAge: 60 * 60 * 24, // 1 day
      });
      return c.redirect(basePath);
    } else {
      return c.text("Invalid credentials", 401);
    }
  });

  // Logout route
  app.get("/logout", (c) => {
    setCookie(c, "isAuthenticated", "false", {
      httpOnly: true,
      path: "/",
      maxAge: 0,
    });
    return c.redirect("/login");
  });

  showRoutes(app);

  serve({ fetch: app.fetch, port: 3000 }, ({ address, port }) => {
    console.log(`Running on ${address}:${port}...`);
  });
};

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
