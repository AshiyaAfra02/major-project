import { NextResponse, type NextRequest } from "next/server";
import { Prisma } from "@prisma/client";
import { ZodError } from "zod";
import { MlError } from "@/lib/mlClient";

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    Object.setPrototypeOf(this, HttpError.prototype);
    this.status = status;
  }
}

export function jsonError(status: number, message: string, extra: Record<string, unknown> = {}) {
  return NextResponse.json({ error: message, ...extra }, { status });
}

export async function readJson(req: NextRequest): Promise<unknown> {
  try {
    return await req.json();
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

/** Converts any thrown error into a safe JSON response (no stack traces or secrets leak out). */
export function handleError(e: unknown) {
  if (e instanceof HttpError) return jsonError(e.status, e.message);

  if (e instanceof ZodError) {
    return jsonError(400, "Invalid request.", {
      issues: e.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
    });
  }

  if (e instanceof MlError) {
    console.error(`[ml-service] ${e.status}: ${e.message}`);
    if (e.status === 422) return jsonError(422, e.message);
    return jsonError(502, "The ML service is unavailable or still waking up. Please try again in a minute.");
  }

  if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2025") {
    return jsonError(404, "Not found.");
  }

  console.error(e);
  return jsonError(500, "Internal server error.");
}
