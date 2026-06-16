import dotenv from "dotenv";

dotenv.config();

const getEnv = (key: string, required = true): string => {
  const value = process.env[key];
  if (!value && required) {
    throw new Error(`Environment variable ${key} is required but not set.`);
  }

  return value as string;
};

const env = {
  port: parseInt(getEnv("PORT", false) || "3000", 10),
  nodeEnv: getEnv("NODE_ENV", false) || "development",
  databaseUrl: getEnv("DATABASE_URL"),
  cookieSecret: getEnv("COOKIE_SECRET"),
};

export default env;
