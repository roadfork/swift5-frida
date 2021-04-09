import { types, basictype, typeshelper } from './types';
import { api, apihelper } from './api';
import { instances, instanceshelper } from './instances';

var Swift5 = {};
Swift5.api = api;
Swift5.apihelper = apihelper;

Swift5.basictype = basictype;
Swift5.types = types;
Swift5.typeshelper = typeshelper;

Swift5.instances = instances;
Swift5.instanceshelper = instanceshelper;

// make Swift5 available to other scripts and the repl
global.Swift5 = Swift5;
export { Swift5 };
