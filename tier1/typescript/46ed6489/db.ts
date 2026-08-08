export const pool = {
  query(text: string, values?: unknown[]): unknown {
    return { text, values };
  },
};
