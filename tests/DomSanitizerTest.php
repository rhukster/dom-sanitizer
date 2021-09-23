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
    
    public function testCompromisedSVG(): void
    {
        $bad_svg = file_get_contents('./tests/bad.svg');
        $good_svg = file_get_contents('./tests/good.svg');
        $sanitizer = new DOMSanitizer(DOMSanitizer::SVG);

        $this->assertEquals(
            $good_svg,
            $sanitizer->sanitize($bad_svg)
        );
    }


}