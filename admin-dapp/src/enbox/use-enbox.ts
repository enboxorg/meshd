import { useContext } from "react";

import { EnboxContext } from "./EnboxProvider";

export function useEnbox() {
  const context = useContext(EnboxContext);
  if (!context) {
    throw new Error("useEnbox must be used within EnboxProvider");
  }
  return context;
}
