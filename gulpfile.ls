/**
 * @package Ronion
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
gulp = require('gulp')

require('build-gbu')('src/index.js', 'ronion', 'ronion.browser', [], gulp)
# Hacky way to replace `minify` task from `build-gbu` with same name task from `build-gc`
require('build-gc')('dist/ronion.browser.js', 'dist/ronion.browser.min.js', 'src/externs.js', {
	task	: (task, func) !->
		gulp.task(task, ['browserify'], func)
})
