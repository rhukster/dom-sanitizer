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
            'remove-wrapper-tags' => false,
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

        $this->assertEqualHtml(
            $good_svg,
            $sanitizer->sanitize($bad_svg)
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

    protected function assertEqualHtml($expected, $actual)
    {
        $from = ['/\>[^\S ]+/s', '/[^\S ]+\</s', '/(\s)+/s', '/> </s'];
        $to   = ['>', '<', '\\1', '><'];
        $this->assertEquals(
            preg_replace($from, $to, $expected),
            preg_replace($from, $to, $actual)
        );
    }


}