import {
  ObjectDefineProperties,
  ObjectGetOwnPropertyDescriptors,
  ObjectGetPrototypeOf,
  ObjectSetPrototypeOf,
  ObjectValues,
  ReflectConstruct,
} from "../primordials.mjs";

export class JSTransferable {}

// deno-lint-ignore ban-types
export function makeTransferable(obj: object): JSTransferable {
  // If the object is already transferable, skip all this.
  if (obj instanceof JSTransferable) return obj;
  const inst = ReflectConstruct(JSTransferable, [], obj.constructor);
  const properties = ObjectGetOwnPropertyDescriptors(obj);
  const propertiesValues = ObjectValues(properties);
  for (let i = 0; i < propertiesValues.length; i++) {
    // We want to use null-prototype objects to not rely on globally mutable
    // %Object.prototype%.
    ObjectSetPrototypeOf(propertiesValues[i], null);
  }
  ObjectDefineProperties(inst, properties);
  ObjectSetPrototypeOf(inst, ObjectGetPrototypeOf(obj));
  return inst;
}

export const kClone = Symbol("kClone");
export const kDeserialize = Symbol("kDeserialize");

export default {
  JSTransferable,
  makeTransferable,
  kClone,
  kDeserialize,
};
