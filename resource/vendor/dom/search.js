/*!
 * Copyright (c) 2017, Park Alter (pseudonym)
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php
 *
 * https://github.com/worldmobilecoin/wmcc-explorer
 * search.js - jquery Document Object Model for wmcc_explorer.
 */

const DOM_Search = function(){
  $(document).on("click","header #nav_search", (e) => {
    const hash = $(e.target).prev('input').val();
    window.location.href = `/search/${hash.trim()}`;
  });

  $(document).on("keyup", "header .search input", function (e) {
    if (e.keyCode == 13) {
      const hash = $(e.target).val();
      window.location.href = `/search/${hash.trim()}`;
    }
  });
}();