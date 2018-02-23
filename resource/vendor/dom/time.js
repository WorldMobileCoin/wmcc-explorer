/*!
 * Copyright (c) 2017, Park Alter (pseudonym)
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php
 *
 * https://github.com/worldmobilecoin/wmcc-explorer
 * time.js - jquery Document Object Model for wmcc_explorer.
 */

const DOM_Time = function(){
  const interval = Math.floor((Math.random() * 10) + 10);
  setInterval(() => { 
    $('.time').each(function(i, o) {
      const ts = parseInt($(o).attr('value'), 10);
      $(o).html(age(ts));
    });
  }, interval*1000);
}();

/*
 * Helpers
 */

function age(time, bool) {
  let d = bool ? time : Math.abs(Date.now()/1000 - time);
  let o = '';
  let r = {};
  let c = 0;
  let z = '';
  const s = {
    year: 31536000,
    month: 2592000,
    week: 604800,
    day: 86400,
    hour: 3600,
    minute: 60,
    second: 1
  }

  Object.keys(s).forEach(function(i){
    r[i] = Math.floor(d / s[i]);
    d -= r[i] * s[i];
    if (r[i] && c<2) {
      z = (r[i] < 10) ? `0${r[i]}`: r[i];
      c++;
      o += ` ${z} ${i}${r[i] > 1 ? 's':''}`;
    }
  });
  if (!o)
    return 'Just now';
  return `${o}${bool ? '':' ago'}`;
}