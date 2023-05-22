import fastify from "fastify";
import fastifyCors from "@fastify/cors";
import { PrismaClient } from "@prisma/client";
import * as bcrypt from "bcryptjs";
import fastifyJwt from "@fastify/jwt";

const server = fastify();
server.register(fastifyCors);
server.register(fastifyJwt, { secret: "mysupersecret" });
server.listen({ port: 3000 }, () => console.log("Server is running"));

const prisma = new PrismaClient();

server.post<{
  Body: {
    name: string;
    email: string;
    password: string;
  };
}>("/register", async (request, reply) => {
  const { password } = request.body;

  try {
    const encryptedHash = bcrypt.hashSync(password, 12);

    const user = await prisma.user.create({
      data: { ...request.body, password: encryptedHash },
    });

    reply.status(201).send(user);
  } catch (error) {
    reply.send(error);
  }
});

server.post<{
  Body: {
    email: string;
    password: string;
  };
}>("/authentication", async (request, reply) => {
  const { email, password } = request.body;
  try {
    const user = await prisma.user.findFirst({
      where: { email },
    });

    if (!user) throw new Error("E-mail or password incorrect");

    const comparedPassword = bcrypt.compareSync(password, user.password);

    if (!comparedPassword) throw new Error("E-mail or password incorrect");

    const token = server.jwt.sign({ id: user.id });

    reply
      .status(200)
      .send({ access_token: token, user: { ...user, password: undefined } });
  } catch (error) {
    reply.send(error);
  }
});

server.route({
  method: "GET",
  url: "/dashboard",
  preHandler: (request) => request.jwtVerify(),
  handler: async function (request, reply) {
    try {
      const users = await prisma.user.findMany({
        select: { id: true, name: true, email: true },
      });
      reply.send(users);
    } catch (error) {
      reply.send(error);
    }
  },
});
