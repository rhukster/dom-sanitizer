<?php

/**
 * @package    Rhukster\DomSanitizer
 *
 * @copyright  Copyright (c) Andy Miller. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Rhukster\DomSanitizer;

class DOMSanitizer
{
    const HTML = 1;
    const SVG = 2;
    const MATHML = 3;

    // Quotes inside url() are optional per CSS Values 4 §4.4, and `data:` is
    // as much a resource load as http:. Requiring a quote here let
    // `url(//evil.example/x)` through on every attribute. (GHSA-jfrr-ch68-f2w9)
    const EXTERNAL_URL = "/url\s*\(\s*[\"']?\s*(ftp:\/\/|http:\/\/|https:\/\/|\/\/|data:)/i";
    const JAVASCRIPT_ATTR = "/(\s(?:href|xlink\:href)\s*=\s*\"javascript:.*?\")/i";
    const SNEAKY_ONLOAD = "/(\s(?:href|xlink\:href)\s*=\s*\"data:.*onload.*?\")/i";
    const NAMESPACE_TAGS = '/xmlns[^=]*="[^"]*"/i';
    const HTML_TAGS = "~<(?:!DOCTYPE|/?(?:html|body))[^>]*>\s*~i";
    const PHP_TAGS = '/<\?(=|php)(.+?)\?>/i';
    const XML_TAGS = '/<\?xml.*\?>/i';
    const WHITESPACE_FROM = ['/\>[^\S ]+/s', '/[^\S ]+\</s', '/(\s)+/s', '/> </s'];
    const WHITESPACE_TO =  ['>', '<', '\\1', '><'];
    const HTML_COMMENTS = '/<!--.*?-->/s';
    // An unterminated `/*` runs to end-of-input in CSS, so the closer is optional.
    const CSS_COMMENTS = '~/\*.*?(?:\*/|$)~s';
    // Schemes that make the browser fetch something off-origin.
    const CSS_EXTERNAL_SCHEME = '(?:https?:|ftp:|\/\/|data:)';

    private static $root = ['html', 'body'];
    private static $html = ['a', 'abbr', 'acronym', 'address', 'area', 'article', 'aside', 'audio', 'b', 'bdi', 'bdo', 'big', 'blink', 'blockquote', 'body', 'br', 'button', 'canvas', 'caption', 'center', 'cite', 'code', 'col', 'colgroup', 'content', 'data', 'datalist', 'dd', 'decorator', 'del', 'details', 'dfn', 'dialog', 'dir', 'div', 'dl', 'dt', 'element', 'em', 'fieldset', 'figcaption', 'figure', 'font', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'hr', 'html', 'i', 'img', 'input', 'ins', 'kbd', 'label', 'legend', 'li', 'main', 'map', 'mark', 'marquee', 'menu', 'menuitem', 'meter', 'nav', 'nobr', 'ol', 'optgroup', 'option', 'output', 'p', 'picture', 'pre', 'progress', 'q', 'rp', 'rt', 'ruby', 's', 'samp', 'section', 'select', 'shadow', 'small', 'source', 'spacer', 'span', 'strike', 'strong', 'style', 'sub', 'summary', 'sup', 'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'time', 'tr', 'track', 'tt', 'u', 'ul', 'var', 'video', 'wbr'];
    private static $svg = ['svg', 'a', 'altglyph', 'altglyphdef', 'altglyphitem', 'animatecolor', 'animatemotion', 'animatetransform', 'circle', 'clippath', 'defs', 'desc', 'ellipse', 'filter', 'font', 'g', 'glyph', 'glyphref', 'hkern', 'image', 'line', 'lineargradient', 'marker', 'mask', 'metadata', 'mpath', 'path', 'pattern', 'polygon', 'polyline', 'radialgradient', 'rect', 'stop', 'style', 'switch', 'symbol', 'text', 'textpath', 'title', 'tref', 'tspan', 'view', 'vkern'];
    private static $svg_filters = ['feblend', 'fecolormatrix', 'fecomponenttransfer', 'fecomposite', 'feconvolvematrix', 'fediffuselighting', 'fedisplacementmap', 'fedistantlight', 'feflood', 'fefunca', 'fefuncb', 'fefuncg', 'fefuncr', 'fegaussianblur', 'femerge', 'femergenode', 'femorphology', 'feoffset', 'fepointlight', 'fespecularlighting', 'fespotlight', 'fetile', 'feturbulence'];
    private static $svg_disallowed = ['animate', 'color-profile', 'cursor', 'discard', 'fedropshadow', 'feimage', 'font-face', 'font-face-format', 'font-face-name', 'font-face-src', 'font-face-uri', 'foreignobject', 'hatch', 'hatchpath', 'mesh', 'meshgradient', 'meshpatch', 'meshrow', 'missing-glyph', 'script', 'set', 'solidcolor', 'unknown', 'use'];
    private static $math_ml = ['math', 'menclose', 'merror', 'mfenced', 'mfrac', 'mglyph', 'mi', 'mlabeledtr', 'mmultiscripts', 'mn', 'mo', 'mover', 'mpadded', 'mphantom', 'mroot', 'mrow', 'ms', 'mspace', 'msqrt', 'mstyle', 'msub', 'msup', 'msubsup', 'mtable', 'mtd', 'mtext', 'mtr', 'munder', 'munderover'];
    private static $math_ml_disallowed = ['maction', 'maligngroup', 'malignmark', 'mlongdiv', 'mscarries', 'mscarry', 'msgroup', 'mstack', 'msline', 'msrow', 'semantics', 'annotation', 'annotation-xml', 'mprescripts', 'none'];
    private static $html_attr = ['accept', 'action', 'align', 'alt', 'autocapitalize', 'autocomplete', 'autopictureinpicture', 'autoplay', 'background', 'bgcolor', 'border', 'capture', 'cellpadding', 'cellspacing', 'checked', 'cite', 'class', 'clear', 'color', 'cols', 'colspan', 'controls', 'controlslist', 'coords', 'crossorigin', 'datetime', 'decoding', 'default', 'dir', 'disabled', 'disablepictureinpicture', 'disableremoteplayback', 'download', 'draggable', 'enctype', 'enterkeyhint', 'face', 'for', 'headers', 'height', 'hidden', 'high', 'href', 'hreflang', 'id', 'inputmode', 'integrity', 'ismap', 'kind', 'label', 'lang', 'list', 'loading', 'loop', 'low', 'max', 'maxlength', 'media', 'method', 'min', 'minlength', 'multiple', 'muted', 'name', 'noshade', 'novalidate', 'nowrap', 'open', 'optimum', 'pattern', 'placeholder', 'playsinline', 'poster', 'preload', 'pubdate', 'radiogroup', 'readonly', 'rel', 'required', 'rev', 'reversed', 'role', 'rows', 'rowspan', 'spellcheck', 'scope', 'selected', 'shape', 'size', 'sizes', 'span', 'srclang', 'start', 'src', 'srcset', 'step', 'style', 'summary', 'tabindex', 'title', 'translate', 'type', 'usemap', 'valign', 'value', 'width', 'xmlns', 'slot'];
    private static $svg_attr = ['accent-height', 'accumulate', 'additive', 'alignment-baseline', 'ascent', 'attributename', 'attributetype', 'azimuth', 'basefrequency', 'baseline-shift', 'begin', 'bias', 'by', 'class', 'clip', 'clippathunits', 'clip-path', 'clip-rule', 'color', 'color-interpolation', 'color-interpolation-filters', 'color-profile', 'color-rendering', 'cx', 'cy', 'd', 'dx', 'dy', 'diffuseconstant', 'direction', 'display', 'divisor', 'dur', 'edgemode', 'elevation', 'end', 'fill', 'fill-opacity', 'fill-rule', 'filter', 'filterunits', 'flood-color', 'flood-opacity', 'font-family', 'font-size', 'font-size-adjust', 'font-stretch', 'font-style', 'font-variant', 'font-weight', 'fx', 'fy', 'g1', 'g2', 'glyph-name', 'glyphref', 'gradientunits', 'gradienttransform', 'height', 'href', 'id', 'image-rendering', 'in', 'in2', 'k', 'k1', 'k2', 'k3', 'k4', 'kerning', 'keypoints', 'keysplines', 'keytimes', 'lang', 'lengthadjust', 'letter-spacing', 'kernelmatrix', 'kernelunitlength', 'lighting-color', 'local', 'marker-end', 'marker-mid', 'marker-start', 'markerheight', 'markerunits', 'markerwidth', 'maskcontentunits', 'maskunits', 'max', 'mask', 'media', 'method', 'mode', 'min', 'name', 'numoctaves', 'offset', 'operator', 'opacity', 'order', 'orient', 'orientation', 'origin', 'overflow', 'paint-order', 'path', 'pathlength', 'patterncontentunits', 'patterntransform', 'patternunits', 'points', 'preservealpha', 'preserveaspectratio', 'primitiveunits', 'r', 'rx', 'ry', 'radius', 'refx', 'refy', 'repeatcount', 'repeatdur', 'restart', 'result', 'rotate', 'scale', 'seed', 'shape-rendering', 'specularconstant', 'specularexponent', 'spreadmethod', 'startoffset', 'stddeviation', 'stitchtiles', 'stop-color', 'stop-opacity', 'stroke-dasharray', 'stroke-dashoffset', 'stroke-linecap', 'stroke-linejoin', 'stroke-miterlimit', 'stroke-opacity', 'stroke', 'stroke-width', 'style', 'surfacescale', 'systemlanguage', 'tabindex', 'targetx', 'targety', 'transform', 'text-anchor', 'text-decoration', 'text-rendering', 'textlength', 'type', 'u1', 'u2', 'unicode', 'values', 'viewbox', 'visibility', 'version', 'vert-adv-y', 'vert-origin-x', 'vert-origin-y', 'width', 'word-spacing', 'wrap', 'writing-mode', 'xchannelselector', 'ychannelselector', 'x', 'x1', 'x2', 'xmlns', 'xlink:href', 'y', 'y1', 'y2', 'z', 'zoomandpan'];
    private static $math_ml_attr = ['accent', 'accentunder', 'align', 'bevelled', 'close', 'columnsalign', 'columnlines', 'columnspan', 'denomalign', 'depth', 'dir', 'display', 'displaystyle', 'encoding', 'fence', 'frame', 'height', 'href', 'id', 'largeop', 'length', 'linethickness', 'lspace', 'lquote', 'mathbackground', 'mathcolor', 'mathsize', 'mathvariant', 'maxsize', 'minsize', 'movablelimits', 'notation', 'numalign', 'open', 'rowalign', 'rowlines', 'rowspacing', 'rowspan', 'rspace', 'rquote', 'scriptlevel', 'scriptminsize', 'scriptsizemultiplier', 'selection', 'separator', 'separators', 'stretchy', 'subscriptshift', 'supscriptshift', 'symmetric', 'voffset', 'width', 'xmlns'];
    private static $special_cases = ['data-', 'aria-'];

    protected $document_type;

    protected $allowed_tags = [];
    protected $allowed_attributes = [];
    protected $disallowed_tags = [];
    protected $disallowed_attributes = [];

    protected $options = [
        'remove-namespaces' => false,
        'remove-php-tags' => true,
        'remove-html-tags' => true,
        'remove-xml-tags' => true,
        'compress-output' => true,
    ];

    /**
     * Constructor that takes an optional DOM type
     *
     * @param int $type The type of DOM you will be sanitizing HTML/SVG/MathML
     */
    public function __construct(int $type = self::HTML)
    {
        $this->document_type = $type;

        switch ($type) {
            case self::SVG:
                $this->allowed_tags = array_unique(array_merge(self::$root, self::$svg, self::$svg_filters));
                $this->allowed_attributes = self::$svg_attr;
                $this->disallowed_tags = self::$svg_disallowed;
                break;
            case self::MATHML:
                $this->allowed_tags = array_unique(array_merge(self::$root, self::$math_ml));
                $this->allowed_attributes = self::$math_ml_attr;
                $this->disallowed_tags = self::$math_ml_disallowed;
                break;
            default:
                $this->allowed_tags = array_unique(array_merge(self::$root, self::$html, self::$svg, self::$svg_filters, self::$math_ml));
                $this->allowed_attributes = array_unique(array_merge(self::$html_attr, self::$svg_attr, self::$math_ml_attr));
                $this->disallowed_tags = array_unique(array_merge(self::$svg_disallowed, self::$math_ml_disallowed));
        }
    }

    /**
     * Sanitize an HTML-style DOM string
     *
     * @param string $dom_content
     * @param array $options
     * @return string
     */
    public function sanitize(string $dom_content, array $options = []): string
    {
        $options = array_merge($this->options, $options);

        if ($options['remove-namespaces']) {
            $dom_content = preg_replace(self::NAMESPACE_TAGS, '', $dom_content);
        }

        if ($options['remove-php-tags']) {
            $dom_content = preg_replace(self::PHP_TAGS, '', $dom_content);
        }

        $document = $this->loadDocument($dom_content);
        $document->preserveWhiteSpace = false;
        $document->strictErrorChecking = false;
        $document->formatOutput = true;

        $tags = array_diff($this->allowed_tags, $this->disallowed_tags);
        $attributes = array_diff($this->allowed_attributes, $this->disallowed_attributes);
        $elements = $document->getElementsByTagName('*');

        for($i = $elements->length; --$i >= 0;) {
            $element = $elements->item($i);
            $tag_name = $element->tagName;
            $tag_name_lower = strtolower($tag_name);
            if(in_array($tag_name_lower, $tags)) {
                if ($tag_name_lower === 'style' && $this->hasDangerousStyleContent($element->textContent)) {
                    $element->parentNode->removeChild($element);
                    continue;
                }
                for($j = $element->attributes->length; --$j >= 0;) {
                    $attr_name = $element->attributes->item($j)->name;
                    $attr_value = $element->attributes->item($j)->textContent;
                    $attr_prefix = $element->attributes->item($j)->prefix;
                    $attr_name_prefix = $attr_name;
                    if ($attr_prefix !== '') {
                        $attr_name_prefix = "$attr_prefix:$attr_name";
                    }
                    if ((!in_array(strtolower($attr_name_prefix), $attributes) && !$this->isSpecialCase($attr_name)) ||
                        $this->isExternalUrl($attr_value) ||
                        $this->isDangerousStyleAttribute($attr_name, $attr_value) ||
                        $this->isDangerousUrl($attr_name_prefix, $attr_value)) {
                        $attr_ns = $element->attributes->item($j)->namespaceURI;
                        $element->removeAttributeNS($attr_ns, $attr_name);
                    }
                }
            } else {
                $element->parentNode->removeChild($element);
            }
        }

        $output = $this->saveDocument($document);

        $output = $this->regexCleaning($output);

        if ($options['remove-html-tags']) {
            $output = preg_replace(self::HTML_TAGS, '', $output);
        }

        if ($options['remove-xml-tags']) {
            $output = preg_replace(self::XML_TAGS, '', $output);
        }

        if ($options['compress-output']) {
                    $output = preg_replace(self::WHITESPACE_FROM, self::WHITESPACE_TO, $output);
                }

        if ($options['compress-output']) {
            $output = preg_replace(self::WHITESPACE_FROM, self::WHITESPACE_TO, $output);
        }

        return trim($output);
    }

    /**
     * Add new additional supported tags
     *
     * @param array $allowed_tags
     */
    public function addAllowedTags(array $allowed_tags): void
    {
        $this->allowed_tags = array_unique(array_merge(array_map('strtolower', $allowed_tags), $this->allowed_tags));
    }

    /**
     * Add new additional supported attributes
     *
     * @param array $allowed_attributes
     */
    public function addAllowedAttributes(array $allowed_attributes): void
    {
        $this->allowed_attributes = array_unique(array_merge(array_map('strtolower', $allowed_attributes), $this->allowed_attributes));
    }

    /**
     * Add new additional unsupported tags
     *
     * @param array $disallowed_tags
     */
    public function addDisallowedTags(array $disallowed_tags): void
    {
        $this->disallowed_tags = array_unique(array_merge(array_map('strtolower', $disallowed_tags), $this->disallowed_tags));
    }

    /**
     * Add new additional unsupported attributes
     *
     * @param array $disallowed_attributes
     */
    public function addDisallowedAttributes(array $disallowed_attributes): void
    {
        $this->disallowed_attributes = array_unique(array_merge(array_map('strtolower', $disallowed_attributes), $this->disallowed_attributes));
    }

    /**
     * Get all the current allowed tags
     *
     * @return array|string[]
     */
    public function getAllowedTags(): array
    {
        return $this->allowed_tags;
    }

    /**
     * Sets the current allowed tags
     *
     * @param array|string[] $allowed_tags
     */
    public function setAllowedTags(array $allowed_tags): void
    {
        $this->allowed_tags = $allowed_tags;
    }

    /**
     * Get all the current allowed attributes
     *
     * @return array|string[]
     */
    public function getAllowedAttributes(): array
    {
        return $this->allowed_attributes;
    }

    /**
     * Sets the current allowed attributes
     *
     * @param array|string[] $allowed_attributes
     */
    public function setAllowedAttributes(array $allowed_attributes): void
    {
        $this->allowed_attributes = $allowed_attributes;
    }

    /**
     * Gets all the current disallowed tags
     *
     * @return array|string[]
     */
    public function getDisallowedTags(): array
    {
        return $this->disallowed_tags;
    }

    /**
     * Sets the current disallowed tags
     *
     * @param array|string[] $disallowed_tags
     */
    public function setDisallowedTags(array $disallowed_tags): void
    {
        $this->disallowed_tags = $disallowed_tags;
    }

    /**
     * Gets all the current disallowed attributes
     *
     * @return array|string[]
     */
    public function getDisallowedAttributes(): array
    {
        return $this->disallowed_attributes;
    }

    /**
     * Sets the current disallowed attributes
     *
     * @param array|string[] $disallowed_attributes
     */
    public function setDisallowedAttributes($disallowed_attributes): void
    {
        $this->disallowed_attributes = $disallowed_attributes;
    }

    /**
     * Determines if the attribute is a special case, e.g. (data-, aria-)
     *
     * @param $attr_name
     * @return bool
     */
    protected function isSpecialCase($attr_name): bool
    {
        return $this->startsWith($attr_name, self::$special_cases);
    }

    /**
     * Determines if the attribute value is an external link
     *
     * @param $attr_value
     * @return bool
     */
    protected function isExternalUrl($attr_value): bool
    {
        return preg_match(self::EXTERNAL_URL, $attr_value);
    }

    /**
     * Determines if an inline `style` attribute carries CSS that would load an
     * external resource or execute.
     *
     * The `<style>` *element* has run its text through hasDangerousStyleContent()
     * since GHSA-93vf-569f-22cq, which normalizes CSS escapes and catches
     * `@import`, `expression()` and `data:`. Inline `style` *attributes* were
     * only ever checked by the EXTERNAL_URL regex, so the identical payload was
     * blocked in a `<style>` block and waved through as an attribute — including
     * escape forms such as `url(\2f\2f evil.example/x)` that no amount of
     * scheme-matching catches. Reuse the element-side check so both paths agree.
     * (GHSA-jfrr-ch68-f2w9)
     *
     * @param string $attr_name
     * @param $attr_value
     * @return bool
     */
    protected function isDangerousStyleAttribute(string $attr_name, $attr_value): bool
    {
        if (strtolower($attr_name) !== 'style') {
            return false;
        }

        return $this->hasDangerousStyleContent((string) $attr_value);
    }

    /**
     * Determines if an href/xlink:href attribute contains a dangerous URL scheme
     * (javascript:, data: with script content). Normalizes control characters
     * before checking to prevent entity-encoding bypasses (CVE-2026-33172 bypass).
     *
     * @param string $attr_name
     * @param string $attr_value
     * @return bool
     */
    protected function isDangerousUrl(string $attr_name, string $attr_value): bool
    {
        if (!in_array(strtolower($attr_name), ['href', 'xlink:href'])) {
            return false;
        }

        // Strip all ASCII control characters and whitespace (0x00-0x20) to prevent
        // bypasses via tab, newline, CR, null bytes, or other control chars
        $normalized = preg_replace('/[\x00-\x20]+/', '', $attr_value);

        if (preg_match('/^javascript:/i', $normalized)) {
            return true;
        }

        if (preg_match('/^data:.*onload/i', $normalized)) {
            return true;
        }

        return false;
    }

    /**
     * Determines if a <style> element's text content contains CSS that would
     * cause the browser to fetch external resources: @import rules, url()
     * references to external schemes (http, https, ftp, protocol-relative,
     * data:), or legacy IE expression(). CSS hex escapes (\hh ) are decoded
     * first so escape-based bypasses are caught (GHSA-93vf-569f-22cq).
     * Fragment references like url(#gradient) are preserved.
     *
     * @param string $css
     * @return bool
     */
    protected function hasDangerousStyleContent(string $css): bool
    {
        $normalized = $this->normalizeCss($css);

        if (preg_match('/@import\b/i', $normalized)) {
            return true;
        }
        if (preg_match('/url\s*\(\s*["\']?\s*' . self::CSS_EXTERNAL_SCHEME . '/i', $normalized)) {
            return true;
        }
        if (preg_match('/expression\s*\(/i', $normalized)) {
            return true;
        }
        // image-set(), cross-fade() and image() load a resource through a quoted
        // string without ever using url(), and the string can sit behind other
        // arguments or nested functions that a single `[^)]*` regex cannot cross
        // (image-set(url(a.png) 1x, "https://evil" 2x)). A custom property can also
        // carry the string and be pulled in later with var(). Walk the CSS once,
        // string-aware and paren-aware, to catch all of these. (GHSA-ww22-4mqv-x5w3)
        if ($this->hasExternalSchemeInImageContext($normalized)) {
            return true;
        }
        return false;
    }

    /**
     * Off-origin schemes for the CSS string scan, anchored at the start of the
     * string value so `background: "not a url https://x"` in `content` is ignored.
     */
    const CSS_STRING_EXTERNAL_SCHEME = '~^\s*(?:https?:|ftp:|//|data:)~i';

    /**
     * Functions that fetch a resource named by a quoted string argument.
     */
    const CSS_IMAGE_FUNCTIONS = ['image-set', '-webkit-image-set', 'cross-fade', '-webkit-cross-fade', 'image'];

    /**
     * Single string- and paren-aware pass over normalized CSS. Flags a quoted
     * string beginning with an off-origin scheme when it is an argument (at any
     * nesting depth) to an image function, or the value of a custom property that
     * `var()` could later feed into one. Legitimate uses -- a relative image-set
     * candidate, or a URL merely displayed via `content` -- are left alone.
     *
     * @param string $css
     * @return bool
     */
    protected function hasExternalSchemeInImageContext(string $css): bool
    {
        $len = strlen($css);
        $funcStack = [];      // lower-cased function name per open paren
        $prop = '';           // property name of the current declaration
        $readingProp = true;  // true until the declaration's ':'
        $i = 0;

        while ($i < $len) {
            $c = $css[$i];

            // String literal: capture it, then classify.
            if ($c === '"' || $c === "'") {
                $quote = $c;
                $i++;
                $value = '';
                while ($i < $len) {
                    if ($css[$i] === '\\' && $i + 1 < $len) {
                        $value .= $css[$i + 1];
                        $i += 2;
                        continue;
                    }
                    if ($css[$i] === $quote) {
                        break;
                    }
                    $value .= $css[$i];
                    $i++;
                }
                $i++; // past the closing quote (or EOF)

                if (preg_match(self::CSS_STRING_EXTERNAL_SCHEME, $value)) {
                    foreach ($funcStack as $fn) {
                        if (in_array($fn, self::CSS_IMAGE_FUNCTIONS, true)) {
                            return true;
                        }
                    }
                    if (strncmp($prop, '--', 2) === 0) {
                        return true;
                    }
                }
                continue;
            }

            // Function open: the identifier immediately before '(' is its name.
            if ($c === '(') {
                $j = $i - 1;
                $name = '';
                while ($j >= 0 && preg_match('/[a-z0-9\-]/i', $css[$j])) {
                    $name = $css[$j] . $name;
                    $j--;
                }
                $funcStack[] = strtolower($name);
                $i++;
                continue;
            }
            if ($c === ')') {
                array_pop($funcStack);
                $i++;
                continue;
            }

            // Declaration boundaries (only meaningful outside any function).
            if (empty($funcStack)) {
                if ($c === ':') {
                    $readingProp = false;
                    $i++;
                    continue;
                }
                if ($c === ';' || $c === '{' || $c === '}') {
                    $prop = '';
                    $readingProp = true;
                    $i++;
                    continue;
                }
                if ($readingProp && preg_match('/[a-z0-9\-]/i', $c)) {
                    $prop .= $c;
                }
            }

            $i++;
        }

        return false;
    }

    /**
     * Normalizes CSS into the form a browser's tokenizer sees, so the
     * dangerous-token checks cannot be split apart by syntax the browser
     * discards.
     *
     * Order matters:
     *  1. Comments are removed first. As far as the checks are concerned a
     *     comment can sit *inside* a token, so leaving them in means every
     *     token check can be cut in half.
     *  2. CSS escapes are decoded, so `\68 ttps:` is seen as the scheme it is.
     *  3. Comments are stripped a second time, because step 2 can *synthesize*
     *     one: `\2f\2a` decodes to `/*`, which did not exist during step 1.
     *
     * Whitespace is deliberately left alone. It is equally inert to browsers,
     * and collapsing it would risk false positives on legitimate multi-line CSS.
     *
     * @param string $css
     * @return string
     */
    protected function normalizeCss(string $css): string
    {
        $css = $this->stripCssComments($css);

        $css = preg_replace_callback(
            '/\\\\([0-9a-fA-F]{1,6})[ \t\n\r\f]?/',
            function ($m) {
                $code = hexdec($m[1]);
                if ($code <= 0 || $code > 0x10FFFF) {
                    return '';
                }
                return mb_chr($code, 'UTF-8') ?: '';
            },
            $css
        ) ?? $css;
        $css = preg_replace('/\\\\([^0-9a-fA-F\r\n\f])/', '$1', $css) ?? $css;

        return $this->stripCssComments($css);
    }

    /**
     * Removes CSS comments, string-aware.
     *
     * A plain regex treats a `/*` sequence that appears inside a string literal
     * as the start of a comment, so an unterminated one -- `content:"/*"` -- would
     * swallow everything after it, hiding whatever dangerous tokens followed. To a
     * browser that `/*` is just string content, not a comment. Walk the CSS and
     * only strip `/* ... *``/` when outside a `"..."` or `'...'` string. An
     * unterminated real comment still runs to end-of-input.
     *
     * @param string $css
     * @return string
     */
    protected function stripCssComments(string $css): string
    {
        $len = strlen($css);
        $out = '';
        $quote = null;
        $i = 0;

        while ($i < $len) {
            $c = $css[$i];

            if ($quote !== null) {
                $out .= $c;
                if ($c === '\\' && $i + 1 < $len) {
                    $out .= $css[$i + 1];
                    $i += 2;
                    continue;
                }
                if ($c === $quote) {
                    $quote = null;
                }
                $i++;
                continue;
            }

            if ($c === '"' || $c === "'") {
                $quote = $c;
                $out .= $c;
                $i++;
                continue;
            }

            if ($c === '/' && $i + 1 < $len && $css[$i + 1] === '*') {
                $i += 2;
                while ($i < $len && !($css[$i] === '*' && $i + 1 < $len && $css[$i + 1] === '/')) {
                    $i++;
                }
                $i += 2; // past the closing */ (harmless past EOF)
                continue;
            }

            $out .= $c;
            $i++;
        }

        return $out;
    }

    /**
     * Does various regex cleanup
     *
     * @param $output
     * @return string
     */
    protected function regexCleaning(string $output): string
    {
        $output = preg_replace(self::JAVASCRIPT_ATTR, '', $output);
        $output = preg_replace(self::SNEAKY_ONLOAD, '', $output);
        $output = preg_replace(self::HTML_COMMENTS, '', $output);
        return $output;
    }

    /**
     * Loads appropriate DOMDocument object
     *
     * Hardens the loader against XML External Entity (XXE) and
     * billion-laughs attacks by:
     *   - stripping `<!DOCTYPE …>` and any `<!ENTITY …>` declarations from
     *     the input *before* parsing (sanitized SVG/HTML never legitimately
     *     needs a doctype or entity declarations);
     *   - passing `LIBXML_NONET` so the parser cannot make outbound HTTP /
     *     filesystem requests for external entities or DTDs;
     *   - on PHP < 8 (where the default did load external entities),
     *     calling `libxml_disable_entity_loader(true)` for the duration of
     *     the parse. The function is deprecated but still a no-op on PHP 8+.
     *
     * @param string $content
     * @return \DOMDocument
     */
    protected function loadDocument(string $content): \DOMDocument
    {
        $content = self::stripDoctypeAndEntities($content);

        $document = new \DOMDocument();

        $internalErrors = libxml_use_internal_errors(true);
        libxml_clear_errors();

        $previousEntityLoader = null;
        if (\PHP_VERSION_ID < 80000 && function_exists('libxml_disable_entity_loader')) {
            $previousEntityLoader = libxml_disable_entity_loader(true);
        }

        $libxmlOptions = LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING;

        try {
            switch ($this->document_type) {
                case self::SVG:
                case self::MATHML:
                    @$document->loadXML($content, $libxmlOptions);
                    break;
                default:
                    @$document->loadHTML($content, $libxmlOptions);
            }
        } finally {
            if ($previousEntityLoader !== null) {
                libxml_disable_entity_loader($previousEntityLoader);
            }
            libxml_use_internal_errors($internalErrors);
        }

        return $document;
    }

    /**
     * Strip DOCTYPE and ENTITY declarations from a sanitizer input.
     *
     * Sanitized content (SVG/HTML/MathML uploaded by users) has no legitimate
     * use for either, so we excise them before parsing — even with
     * `LIBXML_NONET` and the entity loader disabled, eliminating the
     * declarations entirely is the cleanest defense against future libxml
     * regressions.
     */
    private static function stripDoctypeAndEntities(string $content): string
    {
        $content = preg_replace('/<!DOCTYPE\b[^>]*(?:\[[^\]]*\])?[^>]*>/is', '', $content) ?? $content;
        $content = preg_replace('/<!ENTITY\b[^>]*>/i', '', $content) ?? $content;
        return $content;
    }

    /**
     * Saves appropriate DOMDocument object
     *
     * @param \DOMDocument $document
     * @return false|string
     */
    protected function saveDocument(\DOMDocument $document)
    {

        switch ($this->document_type) {
            case self::SVG:
            case self::MATHML:
                $content = $document->saveXML($document);
                break;
            default:
                $content = $document->saveHTML($document);
        }

        return $content;
    }

    /**
     * Helper method to provide str_starts_with functionality that can take an array of needles
     *
     * @param string $haystack
     * @param $needle
     * @param bool $case_sensitive
     * @return bool
     */
    protected function startsWith(string $haystack, $needle, bool $case_sensitive = true): bool
    {
        $status = false;
        $compare_func = $case_sensitive ? 'mb_strpos' : 'mb_stripos';
        foreach ((array)$needle as $each_needle) {
            $status = $each_needle === '' || $compare_func($haystack, $each_needle) === 0;
            if ($status) {
                break;
            }
        }
        return $status;
    }

}

