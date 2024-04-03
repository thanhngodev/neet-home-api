import User from "../models/user.model.js";
import bcryptjs from "bcryptjs";
import { errorHandler } from "../utils/error.js";
import jwt from "jsonwebtoken";
import {
  EMAIL_REGEX_PATTERN,
  USERNAME_REGEX_PATTERN,
  passwordReg,
} from "../utils/regex.js";
import { ERROR_AUTH } from "../enums/errorCodes/errorCodeAuth.js";
import { successHandler } from "../utils/success.js";

export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;

  if (![username, password, email].every((field) => field && field !== "")) {
    next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0001));
    return;
  }

  if (!EMAIL_REGEX_PATTERN.test(email)) {
    next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0004));
    return;
  }

  if (!USERNAME_REGEX_PATTERN.test(username)) {
    next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0005));
    return;
  }

  const validEmail = await User.findOne({ email });
  const validUsername = await User.findOne({ username });

  if (validEmail || validUsername) {
    next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0002));
    return;
  }

  if (!passwordReg.test(password)) {
    next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0003));
    return;
  }

  const hashedPassword = bcryptjs.hashSync(password);
  const newUser = new User({ username, email, password: hashedPassword });

  try {
    await newUser.save();
    res.status(201).json(successHandler(201, "Signup successfully!!!"));
  } catch (error) {
    next(error);
  }
};

export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  if (![password, email].every((field) => field && field !== "")) {
    next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0001));
    return;
  }

  if (!EMAIL_REGEX_PATTERN.test(email)) {
    next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0006));
    return;
  }

  if (!passwordReg.test(password)) {
    next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0006));
    return;
  }

  try {
    const validUser = await User.findOne({ email });

    if (!validUser) {
      next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0006));
      return;
    }

    const validPassword = bcryptjs.compareSync(password, validUser.password);
    if (!validPassword) {
      next(errorHandler(400, ERROR_AUTH.NEET_AUTH_0006));
      return;
    }

    const token = jwt.sign(
      { id: validUser._id, isAdmin: validUser.isAdmin },
      process.env.JWT_SECRET
    );
    const { password: pass, ...rest } = validUser._doc;
    res
      .status(200)
      .cookie("access_token", token, { httpOnly: true })
      .json(rest);
  } catch (error) {
    next(error);
  }
};

export const google = async (req, res, next) => {
  const { email, name, googlePhotoUrl } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      const token = jwt.sign(
        { id: user._id, isAdmin: user.isAdmin },
        process.env.JWT_SECRET
      );
      const { password: pass, ...rest } = user._doc;
      res
        .status(200)
        .cookie("access_token", token, { httpOnly: true })
        .json(rest);
    } else {
      const generatedPassword =
        Math.random().toString(36).slice(-8) +
        Math.random().toString(36).slice(-8);
      const hashedPassord = bcryptjs.hashSync(generatedPassword, 10);
      const newUser = new User({
        username:
          name.toLowerCase().split(" ").join("") +
          Math.random().toString(9).slice(-4),
        email,
        password: hashedPassord,
        avatar: googlePhotoUrl,
      });

      await newUser.save();
      const token = jwt.sign(
        { id: newUser._id, isAdmin: newUser.isAdmin },
        process.env.JWT_SECRET
      );
      const { password: pass, ...rest } = newUser._doc;
      res
        .status(200)
        .cookie("access_token", token, { httpOnly: true })
        .json(rest);
    }
  } catch (error) {
    next(error);
  }
};
