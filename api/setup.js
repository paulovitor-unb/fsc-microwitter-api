import Koa from "koa"
import cors from "@koa/cors"
import bodyParser from "koa-bodyparser"

import { router } from "./routes.js"

export const app = new Koa()

app.use(cors())
app.use(bodyParser())
app.use(router.routes())
app.use(router.allowedMethods())
