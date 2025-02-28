import { type Interfaces } from "../types.ts";
import { fetcher } from "../utils/fetcher.ts";

export const INTERFACES = $state<string[]>(
  await fetcher
    .get<Interfaces>("/system/interfaces")
    .then((data) => data.interfaces.map((item) => item.id))
    .catch((error) => {
      console.error(error);
      return [];
    })
);
