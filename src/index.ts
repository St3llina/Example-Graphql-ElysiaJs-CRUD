import { Elysia } from "elysia";
import { yoga } from '@elysiajs/graphql-yoga'
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";
import bcrypt from 'bcrypt'

const Prisma = new PrismaClient()

const SECRET_KEY = process.env.SECRET_KEY || ''

interface user {
  email: string,
  username: string,
  password: string
}

interface updateUserType { username?: string | null; email?: string | null; password?: string | null }

const app = new Elysia()

// let user: user[] = []

const createUser = async (_: unknown, { username, email, password }: user) => {
  password = await bcrypt.hash(password, 10);
  const newUser = { username, email, password };
  const createdUser = await Prisma.user.create({
    data: newUser
  })
  return createdUser;
}
const updateUser = async (_: unknown, { id, data }: { id: number, data: updateUserType }) => {
  return await Prisma.user.update({
    where: { id },
    data: {
      username: data.username ?? undefined,
      email: data.email ?? undefined,
      password: data.password ?? undefined
    } 
  })
}
const deleteUser = async (_: unknown, { id }: { id: number }) => {
  return await Prisma.user.delete({
    where: { id }
  })
}

const login = async (_: unknown, { email, password }: { email: string, password: string }) => {
  try {
    const findUser = await Prisma.user.findFirst({
      where: {
        email
      }
    })
    if (findUser) {
      if (await bcrypt.compare(password, findUser.password) == true) {
        const accessToken = jwt.sign({ id: findUser.id, username: findUser.username }, SECRET_KEY, {
          expiresIn: "1h",
        });
        return { 
          message: "Logged successfully.",
          accessToken
        }
      } else {
        return {
          message: "Invalid email or username or password."
        }
      }
    }
    return {
      message: "Invalid email or username or password."
    }
  } catch(error) {
    console.error(error)
  }

} 

const typeDefs = `
  type User {
    id: Int,
    email: String,
    username: String,
    password: String
  }
  input UpdateUser {
  username: String
  email: String
  password: String
  }
  type Query {
    users: [User],
    user(id: Int!): User
  }
  type AcessToken {
    message: String,
    accessToken: String
  }
  type Mutation {
    createUser(username: String!, email: String!, password: String!): User,
    deleteUser(id: Int!): User,
    updateUser(id: Int!, data: UpdateUser!): User,
    login(email: String!, password: String!): AcessToken
  }
`


const resolvers = {
  Query: {
    users: async () => {
      return await Prisma.user.findMany();
    },
    user: async (_: unknown, { id }: { id: number })=> {
      return await Prisma.user.findFirst({
        where: { id }
      })
    }
  },
  Mutation: {
    createUser,
    deleteUser,
    updateUser,
    login
  },
}

app.use(
  yoga({
    typeDefs,
    resolvers,
    context: ({ request }: { request: any })=>{
      const authHeader = request.headers.authorization;
      if (authHeader) {
        const token = authHeader.split(" ")[1];
        if (token) {
          try {
            const user = jwt.verify(token, SECRET_KEY);
            return { user };
          } catch (err) {
            throw new Error("Invalid or expired token");
          }
        }
      }
      return {};
    }
  })
)


app.get("/", () => "Hello Elysia").listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
);
