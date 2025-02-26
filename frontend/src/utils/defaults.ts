import type { Rule, Group } from "../types.ts";
import { INTERFACES } from "../data/interfaces.svelte.ts";

export function defaultGroup(): Group {
  return {
    fixProtect: true,
    id: randomId(),
    interface: INTERFACES.at(0) ?? "",
    name: "",
    color: "#ffffff",
    rules: [],
  };
}

export function defaultRule(): Rule {
  return {
    enable: true,
    id: randomId(),
    name: "",
    rule: "",
    type: "namespace",
  };
}

export function randomId(length = 8) {
  const characters = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    result += characters[randomIndex];
  }

  return result;
}
