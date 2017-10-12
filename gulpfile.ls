/**
 * @package   Ronion
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
browserify	= require('browserify')
compiler	= require('google-closure-compiler-js').gulp()
del			= require('del')
fs			= require('fs')
gulp		= require('gulp')
rename		= require('gulp-rename')
tap			= require('gulp-tap')
DESTINATION	= 'dist'

gulp
	.task('build', ['clean', 'browserify', 'minify'])
	.task('browserify', ['clean'], ->
		gulp.src('src/index.js', {read: false})
			.pipe(tap(
				(file) !->
					file.contents	=
						browserify(
							entries			: file.path
							standalone		: 'ronion'
							builtins		: []
							detectGlobals	: false
						)
							.bundle()
			))
			.pipe(rename(
				basename: 'ronion.browser'
			))
			.pipe(gulp.dest(DESTINATION))
	)
	.task('clean', ->
		del(DESTINATION)
	)
	.task('minify', ['browserify'], ->
		gulp.src("#DESTINATION/ronion.browser.js")
			.pipe(compiler(
				compilationLevel	: 'ADVANCED'
				externs				: [{src: fs.readFileSync('src/externs.js').toString()}]
				jsOutputFile		: 'ronion.browser.min.js'
				languageIn			: 'ES5'
				languageOut			: 'ES5'
				warningLevel		: 'VERBOSE'
			))
			.pipe(gulp.dest(DESTINATION))
	)
