module.exports = class stcAdapter {
  constructor(options, config) {
    this.blockStart = options.blockStart || config.tpl.ld[0];
    this.blockEnd = options.blockStart || config.tpl.rd[0];

    this.variableStart = options.variableStart || config.tpl.ld[1];
    this.variableEnd = options.variableEnd || config.tpl.rd[1];

    this.options = options;
    this.config = config;
  }

  getLsSupportCode() {
    let { blockStart, blockEnd } = this;

    let nlsCookie = this.options.nlsCookie;

    let data = {};

    data['if'] = `
      ${blockStart} 
        lsMap["ua"] = c.Request().Header.Get("User-Agent")
        lsMap["cookies"], _ = c.Cookie("${nlsCookie}")
        if strings.Contains(lsMap["ua"].(string), "MSIE ") == false && lsMap["cookies"] != nil {
      ${blockEnd}`;
    data['else'] = `${blockStart} } else { ${blockEnd}`;
    data['end'] = `${blockStart} } ${blockEnd}`;

    return data;
  }

  getLsConfigCode(appConfig) {
    let { blockStart, blockEnd } = this;

    let configStr = JSON.stringify(appConfig);

    return `${blockStart} 
      stc_ls_config, _ = simplejson.NewJson([]byte(\`${configStr}\`))
    ${blockEnd}`;
  }

  getLsBaseCode() {
    let { blockStart, blockEnd } = this;

    let name = 'stc_ls_base_flag';

    let data = {};

    data['if'] = ``;
    data['end'] = ``;
    // data['if'] = `${blockStart} if http_${name} == nil {
    //   http_${name} := true
    // }${blockEnd}`;
    // data['end'] = '';

    return data;
  }

  getLsParseCookieCode() {
    let { blockStart, blockEnd } = this;

    let lsCookie = this.options.lsCookie;

    return `
    ${blockStart}
    stc_ls_cookie := ""
    ls_cookie, _ := c.Cookie("stc_mlook")
    if ls_cookie != nil {
      stc_ls_cookie = ls_cookie.Value
    }
    stc_cookie_length := len(stc_ls_cookie)
    for i := 0; i < stc_cookie_length; i += 2 {
      stc_ls_cookies[ string(stc_ls_cookie[i]) ] = string(stc_ls_cookie[i+1])
    }
    ${blockEnd}
    `;
  }

  getLsConditionCode(lsValue) {
    let { blockStart, blockEnd, variableStart, variableEnd } = this;

    let data = {};

    data['if'] = `
    ${blockStart}
      stc_ls_config_key = stc_ls_config.Get("${lsValue}").MustMap()
      lsMap["ls_cookie"] = stc_ls_cookies[ stc_ls_config_key["key"].(string) ]
      if stc_ls_config_key["version"].(string) == lsMap["ls_cookie"] {
    ${blockEnd}`;
    data['else'] = `${blockStart} } else { ${blockEnd}`;
    data['end'] = `${blockStart} } ${blockEnd}`;
    data['key'] = `${variableStart} stc_ls_config.Get("${lsValue}")["key"] ${variableEnd}`;
    data['version'] = `${variableStart} stc_ls_config.Get("${lsValue}")["version"] ${variableEnd}`;

    return data;
  }
};