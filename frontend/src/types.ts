declare global {
  interface WindowEventMap {
    rule_drop: CustomEvent<{
      from_group_index: number;
      from_rule_index: number;
      to_group_index: number;
      to_rule_index: number;
    }>;
  }
}

export type Group = {
  id: string;
  name?: string;
  color: string;
  interface: string;
  enable: boolean;
  rules: Rule[];
};

export type Rule = {
  enable: boolean;
  id: string;
  name?: string;
  rule: string;
  type: RuleTypeValue;
};

export const RULE_TYPES = [
  { value: "namespace", label: "Namespace" },
  { value: "wildcard", label: "Wildcard" },
  { value: "regex", label: "Regex" },
  { value: "domain", label: "Domain" },
];

export type RuleTypes = typeof RULE_TYPES;
export type RuleTypeValue = RuleTypes[number]["value"];

export type Interfaces = {
  interfaces: {
    id: string;
  }[];
};

export type Metadata = {
  version: string;
  types: { value: string; label: string }[];
  interfaces: string[];
};
