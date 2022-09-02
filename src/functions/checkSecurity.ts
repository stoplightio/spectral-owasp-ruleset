import { createRulesetFunction, IFunctionResult } from '@stoplight/spectral-core';

export default createRulesetFunction({
  input: null,
  options: {
    type: 'object',
    additionalProperties: false,
    properties: {
      value: true,
    },
    required: ['value'],
  },
}, (input, options): IFunctionResult[] => {
  
  console.log("input", input);
  console.log("options", options);

  return [
    {
      message: `HELLO WORLD FROM CHECK CHECK SECURITY.`,
    },
  ];
});
