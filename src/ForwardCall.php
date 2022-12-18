<?php

namespace sizeg\jwt;

use BadMethodCallException;
use Error;

trait ForwardCall
{

    /**
     * Forward a method call to the given object.
     *
     * @param mixed $object
     * @param string $name
     * @param array $params
     * @return mixed
     *
     * @throws BadMethodCallException
     */
    protected function forward($object, string $name, array $params)
    {
        try {
            return $object->{$name}(...$params);
        } catch (Error|BadMethodCallException $e) {
            if (!preg_match('#^Call to undefined method (?P<class>[^:]+)::(?P<method>[^\(]+)\(\)$#', $e->getMessage(), $m)) {
                throw $e;
            }

            if ($m['class'] != get_class($object) ||
                $m['method'] != $name) {
                throw $e;
            }

            static::throwBadMethodCallException($name);
        }
    }

    /**
     * Forward a method call to the given object, returning $this if the forwarded call returned itself.
     *
     * @param mixed $object
     * @param string $name
     * @param array $params
     * @return mixed
     *
     */
    protected function forwardSelf($object, string $name, array $params)
    {
        $result = $this->forward($object, $name, $params);

        if ($result === $object) {
            return $this;
        }

        return $result;
    }

    /**
     * Throw a bad method call exception for the given method.
     *
     * @param string $name
     * @return void
     *
     * @throws BadMethodCallException
     */
    protected static function throwBadMethodCallException(string $name)
    {
        throw new BadMethodCallException(sprintf('Call to undefined method %s::%s()', static::class, $name));
    }
}