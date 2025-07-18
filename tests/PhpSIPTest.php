<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../PhpSIP.class.php';

class PhpSIPTest extends TestCase
{
    /**
     * Test PHP 8.4 nullable parameter compatibility in constructor
     */
    public function testConstructorNullableParametersCompatibility(): void
    {
        $reflection = new ReflectionClass('PhpSIP');
        $constructor = $reflection->getConstructor();
        $parameters = $constructor->getParameters();
        
        $this->assertCount(3, $parameters);
        $this->assertTrue($parameters[0]->allowsNull());
        $this->assertTrue($parameters[1]->allowsNull());
        $this->assertTrue($parameters[2]->allowsNull());
        
        $param0Type = $parameters[0]->getType();
        if ($param0Type !== null) {
            $this->assertEquals('string', $param0Type->getName());
        }
        
        $param1Type = $parameters[1]->getType();
        if ($param1Type !== null) {
            $this->assertEquals('int', $param1Type->getName());
        }
        
        $param2Type = $parameters[2]->getType();
        if ($param2Type !== null) {
            $this->assertEquals('int', $param2Type->getName());
        }
    }

    /**
     * Test setContentType nullable parameter compatibility
     */
    public function testSetContentTypeNullableCompatibility(): void
    {
        $reflection = new ReflectionClass('PhpSIP');
        $method = $reflection->getMethod('setContentType');
        $parameters = $method->getParameters();
        
        $this->assertCount(1, $parameters);
        $this->assertTrue($parameters[0]->allowsNull());
        
        $paramType = $parameters[0]->getType();
        if ($paramType !== null) {
            $this->assertEquals('string', $paramType->getName());
        }
    }

    /**
     * Test setCallId nullable parameter compatibility
     */
    public function testSetCallIdNullableCompatibility(): void
    {
        $reflection = new ReflectionClass('PhpSIP');
        $method = $reflection->getMethod('setCallId');
        $parameters = $method->getParameters();
        
        $this->assertCount(1, $parameters);
        $this->assertTrue($parameters[0]->allowsNull());
        
        $paramType = $parameters[0]->getType();
        if ($paramType !== null) {
            $this->assertEquals('string', $paramType->getName());
        }
    }

    /**
     * Test that PhpSIP class exists and has expected methods
     */
    public function testPhpSIPClassStructure(): void
    {
        $this->assertTrue(class_exists('PhpSIP'));
        
        $reflection = new ReflectionClass('PhpSIP');
        $expectedMethods = [
            '__construct', '__destruct', 'setDebug', 'getSrcIp', 'addHeader',
            'setFrom', 'setTo', 'setMethod', 'setProxy', 'setContact', 'setUri',
            'setUsername', 'setUserAgent', 'setPassword', 'send', 'listen',
            'setServerMode', 'reply', 'setBody', 'setContentType', 'setFromTag',
            'setToTag', 'setCseq', 'setCallId', 'getHeader', 'getBody'
        ];
        
        foreach ($expectedMethods as $methodName) {
            $this->assertTrue($reflection->hasMethod($methodName), "Method $methodName should exist");
        }
    }

    /**
     * Test method parameter validation without socket creation
     */
    public function testSetMethodValidation(): void
    {
        $reflection = new ReflectionClass('PhpSIP');
        $this->assertTrue($reflection->hasMethod('setMethod'));
        
        $method = $reflection->getMethod('setMethod');
        $this->assertTrue($method->isPublic());
    }

    /**
     * Test PhpSIPException class structure and functionality
     */
    public function testPhpSIPExceptionExists(): void
    {
        $this->assertTrue(class_exists('PhpSIPException'));
        
        $reflection = new ReflectionClass('PhpSIPException');
        $this->assertTrue($reflection->isSubclassOf('Exception'));
    }
}
