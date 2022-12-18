<?php

declare(strict_types=1);

namespace sizeg\jwt\Encoding;

use Lcobucci\JWT\ClaimsFormatter as ClaimsFormatterInterface;
use Lcobucci\JWT\Encoding\ChainedFormatter as JwtEncodingChainedFormatter;
use sizeg\jwt\ForwardCall;
use yii\base\Component;
use yii\di\Instance;

final class ChainedFormatter extends Component implements ClaimsFormatterInterface
{
    use ForwardCall;

    /**
     * @var JwtEncodingChainedFormatter
     */
    private JwtEncodingChainedFormatter $chainedFormatter;

    /**
     * @var array
     */
    public array $formatters;

    /**
     * @inheritDoc
     */
    public function init()
    {
        parent::init();

        $formatters = [];
        foreach ($this->formatters as $f) {
            $formatters[] = Instance::ensure($f, ClaimsFormatterInterface::class);
        }

        $this->chainedFormatter = new JwtEncodingChainedFormatter(...$formatters);
    }

    /**
     * @inheritDoc
     */
    public function __call($name, $params)
    {
        return $this->forward($this->chainedFormatter, $name, $params);
    }

    /**
     * @param array $claims
     * @return array
     */
    public function formatClaims(array $claims): array
    {
        return $this->forward($this->chainedFormatter, 'formatClaims', [$claims]);
    }
}