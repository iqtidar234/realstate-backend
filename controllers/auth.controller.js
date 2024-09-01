import bcrypt from "bcrypt";
import prisma from "../lib/prisma.js";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
  const { email, username, password } = req.body;

  try {
    // hash the password
    const hashPassword = await bcrypt.hash(password, 10);

    // save new user to the db
    const newUser = await prisma.user.create({
      data: { email, username, password: hashPassword },
    });
    const { password: userPassword, ...userInfo } = newUser;

    res.status(201).json(userInfo);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "failed to create user" });
  }
};

export const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    // check if user exist or not
    const user = await prisma.user.findUnique({ where: { username } });

    if (!user) return res.status(401).json({ message: "user not found" });

    // check the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid)
      return res.status(401).json({ message: "invalid creadintials" });

    const age = 1000 * 60 * 60 * 24 * 7;

    const token = jwt.sign(
      { id: user.id, isAdmin: true },
      process.env.JWT_SECRET_KEY,
      {
        expiresIn: age,
      }
    );
    const { password: userPassword, ...userInfo } = user;
    res
      .cookie("token", token, { httpOnly: true, maxAge: age })
      .status(200)
      .json(userInfo);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "failed to login" });
  }
};
export const logout = (req, res) => {
  // db operations
  res.clearCookie("token").status(200).json({ message: "Logout Successfully" });
};
