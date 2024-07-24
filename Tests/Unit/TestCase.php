<?php

namespace Tests\Unit;

use ReflectionException;
use ReflectionObject;
use RuntimeException;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    /**
     * Injects $dependency into property $name of $target
     *
     * This is a convenience method for setting a protected or private property in
     * a test subject for the purpose of injecting a dependency.
     *
     * @param  object  $target  The instance which needs the dependency
     * @param  string  $name  Name of the property to be injected
     * @param  mixed  $dependency  The dependency to inject – usually an object but can also be any other type
     * @throws ReflectionException
     */
    protected function inject(object $target, string $name, mixed $dependency): void
    {
        $objectReflection = new ReflectionObject($target);
        $methodNamePart = strtoupper($name[0]).substr($name, 1);
        if ($objectReflection->hasMethod('set'.$methodNamePart)) {
            $methodName = 'set'.$methodNamePart;
            $target->$methodName($dependency);
        } elseif ($objectReflection->hasMethod('inject'.$methodNamePart)) {
            $methodName = 'inject'.$methodNamePart;
            $target->$methodName($dependency);
        } elseif ($objectReflection->hasProperty($name)) {
            $property = $objectReflection->getProperty($name);
            $property->setAccessible(true);
            $property->setValue($target, $dependency);
        } else {
            throw new RuntimeException('Could not inject '.$name.' into object of type '.get_class($target));
        }
    }
}
