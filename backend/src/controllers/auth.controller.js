import bcrypt from "bcryptjs";
import { db } from "../libs/db.js";
import { UserRole } from "../generated/prisma/index.js";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
    const { email, password, name } = req.body;

    try{
    const existingUser = await db.user.findUnique({
        where:{
            email
        }
    })

    if(existingUser){
        return res.status(400).json({
            error:"User already exist"
        })
    }

    const hashedpassword = await bcrypt.hash(password, 10)

    const newUser = await db.user.create({
        data: {
            email, 
            password: hashedpassword,
            name, 
            role: UserRole.USER
        }
    })

    const token = jwt.sign({id:newUser.id}, process.env.JWT_SECRET, {expiresIn: "7d"})

    res.cookie("jwt", token, {
        httpOnly: true, 
        sameSite: "strict",
        secure: process.env.NODE_ENV !== "development",
        maxAge: 1000 * 60 * 60 * 24 * 7 //1000 miliseconds(1second) * 60 = 1 minute * 60 = 1 hour * 24 = one day * 7 = 7 days
    })

    res.status(201).json({
        message: "User created successfully",
        user: {
            id: newUser.id,
            email: newUser.email,
            name: newUser.name,
            role: newUser.role,
            image: newUser.image
        }
    })

    } catch(error)
    {
        console.error("Eror Creating User:", error);
        res.status(500).json({
            error: "Eror creating user"
        })
    }
}

export const login = async (req, res) => {

    const {email, password} = req.body;

    try {
        const user = await db.user.findUnique({
            where: {
                email
            }
        })

        if(!user){
            return res.status(401).json({
                error: "User not found"
            })
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            return res.status(401).json({
                error: "Invalid Credentials"
            })
        }

        const token = jwt.sign({id:user.id}, process.env.JWT_SECRET, {
            expiresIn:"7d"
        })

        res.cookie("jwt", token, {
            httpOnly: true, 
            sameSite: "strict",
            secure: process.env.NODE_ENV !== "development",
            maxAge: 1000 * 60 * 60 * 24 * 7 //1000 miliseconds(1second) * 60 = 1 minute * 60 = 1 hour * 24 = one day * 7 = 7 days
        })
    
        res.status(200).json({
            message: "LoggedIn successfully",
            user:{
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                image: user.image
            }
        })
        
    } catch (error) {
        console.error("Error LoggingIn User:", error);
        res.status(500).json({
            error: "Error LoggingIn user"
        })
    
    }
}

export const logout = async (req, res) => {}

export const check = async (req, res) => {}
