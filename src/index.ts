import { createBullBoard } from "@bull-board/api";
import { BullMQAdapter } from "@bull-board/api/bullMQAdapter";
import { HonoAdapter } from "@bull-board/hono";
import { Queue as QueueMQ, Worker } from "bullmq";
import { Hono } from "hono";
import { showRoutes } from "hono/dev";
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Redis } from 'ioredis';
import dotenv from "dotenv";

dotenv.config();

const redis = new Redis(`${process.env.PRIVATE_REDIS_URL}?family=0`, { maxRetriesPerRequest: null });
const createQueueMQ = (name: string) => new QueueMQ(name, { connection: redis });

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
  app.route(basePath, serverAdapter.registerPlugin());

  showRoutes(app);

  serve({ fetch: app.fetch, port: 3000 }, ({ address, port }) => {
    console.log(`Running on ${address}:${port}...`);
  });
};

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
