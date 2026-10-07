export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    Object.setPrototypeOf(this, ApiError.prototype);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function api<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;

  try {
    res = await fetch(url, { cache: "no-store", ...init });
  } catch {
    throw new ApiError("Network error. Is the server running?", 0);
  }

  const data = await res.json().catch(() => null);

  if (!res.ok) {
    let message: string = data?.error ?? `Request failed (${res.status})`;

    if (Array.isArray(data?.issues) && data.issues.length) {
      message = data.issues
        .map((i: { message: string }) => i.message)
        .join("; ");
    }

    throw new ApiError(message, res.status);
  }

  return data as T;
}
