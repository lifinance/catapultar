export type ConfigOptions = {};

export const config: ConfigOptions = {};

export const Config = {
  set(options: Partial<ConfigOptions>) {
    Object.assign(config, options);
  },
  get(): Readonly<ConfigOptions> {
    return config;
  },
};
