/**
 * Improved Gophish Gulpfile
 * Handles: Vendor JS, App Scripts, and Stylesheets
 */

const gulp = require('gulp');
const rename = require('gulp-rename');
const concat = require('gulp-concat');
const uglify = require('gulp-uglify-es').default;
const cleanCSS = require('gulp-clean-css');
const babel = require('gulp-babel');
const plumber = require('gulp-plumber');
const sourcemaps = require('gulp-sourcemaps');

// === Directory Paths ===
const paths = {
    js: {
        src: 'static/js/src/',
        vendor: 'static/js/src/vendor/',
        app: 'static/js/src/app/',
        dest: 'static/js/dist/',
    },
    css: {
        src: 'static/css/',
        dest: 'static/css/dist/',
    }
};

// === Vendor JS Task ===
function vendorJS() {
    const files = [
        'jquery.js',
        'bootstrap.min.js',
        'moment.min.js',
        'papaparse.min.js',
        'd3.min.js',
        'topojson.min.js',
        'datamaps.min.js',
        'jquery.dataTables.min.js',
        'dataTables.bootstrap.js',
        'datetime-moment.js',
        'jquery.ui.widget.js',
        'jquery.fileupload.js',
        'jquery.iframe-transport.js',
        'sweetalert2.min.js',
        'bootstrap-datetime.js',
        'select2.min.js',
        'core.min.js',
        'highcharts.js',
        'ua-parser.min.js'
    ].map(file => paths.js.vendor + file);

    return gulp.src(files)
        .pipe(plumber())
        .pipe(concat('vendor.min.js'))
        .pipe(uglify())
        .pipe(gulp.dest(paths.js.dest));
}

.pipe(uglify())
// === App JS Task ===
function appScripts() {
    const files = [
        'autocomplete.js',
        'campaign_results.js',
        'campaigns.js',
        'dashboard.js',
        'groups.js',
        'landing_pages.js',
        'sending_profiles.js',
        'settings.js',
        'templates.js',
        'gophish.js',
        'users.js',
        'webhooks.js',
        'passwords.js'
    ].map(file => paths.js.app + file);

    return gulp.src(files)
        .pipe(plumber())
        .pipe(sourcemaps.init())
        .pipe(uglify())
        .pipe(rename({ suffix: '.min' }))
        .pipe(sourcemaps.write('.'))
        .pipe(gulp.dest(paths.js.dest + 'app/'));
}

// === CSS Task ===
function styles() {
    const files = [
        'bootstrap.min.css',
        'main.css',
        'dashboard.css',
        'flat-ui.css',
        'dataTables.bootstrap.css',
        'font-awesome.min.css',
        'chartist.min.css',
        'bootstrap-datetime.css',
        'checkbox.css',
        'sweetalert2.min.css',
        'select2.min.css',
        'select2-bootstrap.min.css'
    ].map(file => paths.css.src + file);

    return gulp.src(files)
        .pipe(plumber())
        .pipe(concat('gophish.min.css'))
        .pipe(cleanCSS({ compatibility: 'ie9' }))
        .pipe(gulp.dest(paths.css.dest));
}

// === Exported Tasks ===
exports.vendorjs = vendorJS;
exports.scripts = appScripts;
exports.styles = styles;
exports.build = gulp.parallel(vendorJS, appScripts, styles);
exports.default = exports.build;
