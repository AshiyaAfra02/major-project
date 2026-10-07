import { AlertStatus, Severity } from "@prisma/client";
import { z } from "zod";

export const scanSchema = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("url"),
      input: z
        .string()
        .trim()
        .min(3, "URL is too short")
        .max(2048, "URL is too long")
        .refine((v) => !/\s/.test(v), "URL must not contain spaces"),
    })
    .strict(),
  z
    .object({
      type: z.literal("text"),
      input: z.string().trim().min(1, "Message is empty").max(5000, "Message is too long (max 5000 characters)"),
    })
    .strict(),
]);

const upper = (v: unknown) => (typeof v === "string" ? v.toUpperCase() : v);

export const alertsQuerySchema = z.object({
  status: z.preprocess(upper, z.nativeEnum(AlertStatus).optional()),
  severity: z.preprocess(upper, z.nativeEnum(Severity).optional()),
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: z.string().min(1).max(50).optional(),
});

export const alertPatchSchema = z
  .object({ status: z.preprocess(upper, z.nativeEnum(AlertStatus)) })
  .strict();

export const idSchema = z.string().min(1).max(50);
