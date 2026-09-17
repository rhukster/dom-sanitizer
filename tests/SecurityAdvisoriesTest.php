<?php declare(strict_types=1);

namespace Rhukster\DomSanitizer;

use PHPUnit\Framework\TestCase;

final class SecurityAdvisoriesTest extends TestCase
{
    /** @dataProvider processingInstructionProvider */
    public function testProcessingInstructionsAreRemoved(int $mode, string $input): void
    {
        $sanitizer = new DOMSanitizer($mode);
        // Output preferences must not disable security filtering.
        $output = $sanitizer->sanitize($input, [
            'remove-php-tags' => false,
            'remove-xml-tags' => false,
            'compress-output' => false,
        ]);
        $this->assertStringNotContainsString('<?x ', $output);
        $this->assertStringNotContainsString('<?xml-stylesheet', $output);
        $this->assertStringNotContainsString('<?php', $output);
        $this->assertStringNotContainsString('onerror', $output);
        $this->assertStringContainsString('safe', $output);
    }

    public static function processingInstructionProvider(): array
    {
        return [
            'reported SVG' => [DOMSanitizer::SVG, '<svg xmlns="http://www.w3.org/2000/svg" viewBox="-1 -1 2 2"><?x ><img src=x onerror=alert(1)><?x?><text>safe</text></svg>'],
            'nested and adjacent instructions' => [DOMSanitizer::SVG, '<svg xmlns="http://www.w3.org/2000/svg"><g><?x one?><?x two?><text>safe</text></g></svg>'],
            'document-level instructions' => [DOMSanitizer::SVG, '<?xml version="1.0"?><?xml-stylesheet href="evil.css"?><svg xmlns="http://www.w3.org/2000/svg"><text>safe</text></svg><?x after?>'],
            'PHP option cannot retain instructions' => [DOMSanitizer::SVG, '<svg xmlns="http://www.w3.org/2000/svg"><?php echo 1; ?><text>safe</text></svg>'],
            'MathML' => [DOMSanitizer::MATHML, '<math xmlns="http://www.w3.org/1998/Math/MathML"><?x ><img src=x onerror=alert(1)><?x?><mi>safe</mi></math>'],
            'HTML' => [DOMSanitizer::HTML, '<div><?x ignored?><span>safe</span></div>'],
        ];
    }

    /** @dataProvider cdataProvider */
    public function testCdataBecomesEscapedText(string $input): void
    {
        $output = (new DOMSanitizer(DOMSanitizer::SVG))->sanitize($input);
        $this->assertStringNotContainsString('<![CDATA[', $output);
        $this->assertStringNotContainsString('<img', $output);
        $this->assertStringContainsString('&lt;img', $output);
    }

    public static function cdataProvider(): array
    {
        return [
            'HTML integration point' => ['<svg xmlns="http://www.w3.org/2000/svg"><desc><![CDATA[ ><img src=x onerror=alert(1)> ]]></desc></svg>'],
            'HTML font breakout' => ['<svg xmlns="http://www.w3.org/2000/svg"><font color="red"/><![CDATA[ ><img src=x onerror=alert(1)> ]]></svg>'],
            'adjacent text and CDATA' => ['<svg xmlns="http://www.w3.org/2000/svg"><text>before<![CDATA[<img>]]><![CDATA[<img>]]>after</text></svg>'],
        ];
    }

    public function testSafeCdataContentIsPreserved(): void
    {
        $input = '<svg xmlns="http://www.w3.org/2000/svg"><style><![CDATA[.safe { fill: red; }]]></style><text><![CDATA[A < B & C]]></text></svg>';
        $output = (new DOMSanitizer(DOMSanitizer::SVG))->sanitize($input);
        $document = new \DOMDocument();
        $this->assertTrue($document->loadXML($output));
        $this->assertSame('.safe { fill: red; }', $document->getElementsByTagName('style')->item(0)->textContent);
        $this->assertSame('A < B & C', $document->getElementsByTagName('text')->item(0)->textContent);
    }

    public function testCommentsCannotHideHtmlMarkup(): void
    {
        $input = '<svg xmlns="http://www.w3.org/2000/svg"><!--><img src=x onerror=alert(1)><!--><text>safe</text></svg>';
        $output = (new DOMSanitizer(DOMSanitizer::SVG))->sanitize($input);
        $this->assertStringNotContainsString('<!--', $output);
        $this->assertStringNotContainsString('<img', $output);
        $this->assertStringContainsString('safe', $output);
    }

    /** @dataProvider dangerousAnimationProvider */
    public function testDangerousAnimationIsRemoved(int $mode, string $tag, string $target, string $values, bool $stripLinks): void
    {
        $sanitizer = new DOMSanitizer($mode);
        if ($stripLinks) {
            // Grav strips the static link, but animation can recreate it.
            $sanitizer->addDisallowedAttributes(['href', 'xlink:href']);
        }
        $input = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:alias="http://www.w3.org/1999/xlink"><a href="#safe"><text>safe</text><' . $tag . ' attributeName="' . $target . '" type="invalid" values="' . $values . '" begin="0s" dur="0.1s" fill="freeze"/></a></svg>';
        $output = $sanitizer->sanitize($input);
        $this->assertStringNotContainsString('<' . strtolower($tag), strtolower($output));
        $this->assertStringContainsString('<text>safe</text>', $output);
    }

    public static function dangerousAnimationProvider(): array
    {
        $cases = [];
        foreach ([DOMSanitizer::SVG, DOMSanitizer::HTML] as $mode) {
            foreach (['animateTransform', 'animateColor', 'animateMotion'] as $tag) {
                foreach (['href', 'xlink:href', 'alias:href', ' HREF ', '&#x68;ref', 'src', 'srcset', 'action', 'poster', 'cite', 'background', 'style', 'onload', 'xmlns'] as $target) {
                    $cases["$mode/$tag/$target"] = [$mode, $tag, $target, "XXX;javascript:alert(1)//", false];
                }
            }
            $cases["$mode/Grav"] = [$mode, 'animateTransform', 'href', "XXX;javascript:alert(1)//", true];
            $cases["$mode/fragment URL"] = [$mode, 'animateTransform', 'href', '#one;#two', false];
        }
        return $cases;
    }

    /** @dataProvider safeAnimationProvider */
    public function testSafeAnimationsArePreserved(int $mode, string $animation): void
    {
        $input = '<svg xmlns="http://www.w3.org/2000/svg"><g>' . $animation . '<text>safe</text></g></svg>';
        $output = (new DOMSanitizer($mode))->sanitize($input);
        $this->assertStringContainsString('values=', $output);
        $this->assertStringContainsString('<' . strtolower(explode(' ', substr($animation, 1))[0]), strtolower($output));
    }

    public static function safeAnimationProvider(): array
    {
        $cases = [];
        foreach ([DOMSanitizer::SVG, DOMSanitizer::HTML] as $mode) {
            foreach (['transform', 'gradientTransform', 'patternTransform'] as $target) {
                $cases["$mode/$target"] = [$mode, '<animateTransform attributeName="' . $target . '" type="rotate" values="0;360" dur="1s"/>'];
            }
            $cases["$mode/color"] = [$mode, '<animateColor attributeName="fill" values="red;blue" dur="1s"/>'];
            $cases["$mode/motion"] = [$mode, '<animateMotion values="0,0;10,10" dur="1s"/>'];
        }
        return $cases;
    }
}
