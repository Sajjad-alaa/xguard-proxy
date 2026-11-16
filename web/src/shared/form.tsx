import { createFormHook } from '@tanstack/react-form';
import { fieldContext, formContext } from './form-context';
import { FormInput } from './xguard-ui/components/form/FormInput/FormInput';

export { useFieldContext, useFormContext } from './form-context';

export const { useAppForm, withForm } = createFormHook({
  fieldContext,
  formContext,
  fieldComponents: {
    FormInput,
  },
  formComponents: {},
});
