import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** shadcn-style class-name combiner used by every UI component. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
