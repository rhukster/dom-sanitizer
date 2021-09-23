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