import Router from "@koa/router"
import { PrismaClient } from "@prisma/client"
import bcrypt from "bcrypt"
import { omit } from "ramda"
import jwt from "jsonwebtoken"

export const router = new Router()

const prisma = new PrismaClient()

router.get("/tweets", async ctx => {
    const [, token] = ctx.request.headers?.authorization?.split(" ") || []
    if (!token) {
        ctx.status = 401
        return
    }

    try {
        jwt.verify(token, process.env.JWT_SECRET)

        const tweets = await prisma.tweets.findMany({
            include: {
                user: true
            }
        })
        ctx.body = tweets.reverse()
    } catch (error) {
        if (typeof error === "JsonWebTokenError") {
            ctx.status = 401
            return
        }

        ctx.status = 500
        return
    }
})

router.post("/tweets", async ctx => {
    const [, token] = ctx.request.headers?.authorization?.split(" ") || []
    if (!token) {
        ctx.status = 401
        return
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET)
        const tweet = await prisma.tweets.create({
            data: {
                text: ctx.request.body.text,
                userId: payload.sub
            }
        })
        ctx.body = tweet
    } catch (error) {
        ctx.status = 401
        return
    }
})

router.post("/signup", async ctx => {
    const SALT_ROUNDS = 10
    const encryptedPassword = bcrypt.hashSync(
        ctx.request.body.password,
        SALT_ROUNDS
    )

    try {
        const user = await prisma.users.create({
            data: {
                name: ctx.request.body.name,
                email: ctx.request.body.email,
                username: ctx.request.body.username,
                password: encryptedPassword
            }
        })
        const accessToken = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, {
            expiresIn: "24h"
        })

        ctx.body = omit(["password"], { ...user, accessToken })
    } catch (error) {
        if (error.meta && !error.meta.target) {
            ctx.status = 422
            ctx.body = "Username or email already exists!"
            return
        }

        ctx.status = 500
        ctx.body = "Server internal error!"
    }
})

router.get("/login", async ctx => {
    const [, token] = ctx.request.headers.authorization.split(" ")
    const [usernameOrEmail, password] = Buffer.from(token, "base64")
        .toString()
        .split(":")

    const user = await prisma.users.findFirst({
        where: {
            OR: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
        }
    })
    if (!user) {
        ctx.status = 401
        return
    }

    const passwordMatches = bcrypt.compareSync(password, user.password)
    if (!passwordMatches) {
        ctx.status = 401
        return
    }

    const accessToken = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, {
        expiresIn: "24h"
    })

    ctx.body = omit(["password"], { ...user, accessToken })
    //ctx.redirect("/")
    //ctx.redirect("/tweets")
})
