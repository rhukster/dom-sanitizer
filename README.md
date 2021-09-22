# DOMSanitizer

A simple but effective DOM/SVG/MathML Sanitizer for PHP 7.4+

## Installation

```sh
composer require rhukster/dom-sanitizer
```

## Usage

### Sanitizing HTML

```php
require Rhukster/DomSanitizer/DomSanitizer

$bad_html = file_get_contents('bad.html');
$sanitizer = new DOMSanitizer();
$good_html = $sanitizer->sanitize($bad_html);
```

### Sanitizing SVG

```php
require Rhukster/DomSanitizer/DomSanitizer

$bad_svg = file_get_contents('bad.svg');
$sanitizer = new DOMSanitizer(DOMSanitizer::SVG);
$good_svg = $sanitizer->sanitize($bad_svg);
```