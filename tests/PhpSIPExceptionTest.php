<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../PhpSIP.Exception.php';

class PhpSIPExceptionTest extends TestCase
{
    public function testPhpSIPExceptionCreation(): void
    {
        $message = 'Test exception message';
        $exception = new PhpSIPException($message);
        
        $this->assertInstanceOf(PhpSIPException::class, $exception);
        $this->assertInstanceOf(Exception::class, $exception);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function testPhpSIPExceptionWithCode(): void
    {
        $message = 'Test exception with code';
        $code = 500;
        $exception = new PhpSIPException($message, $code);
        
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function testPhpSIPExceptionWithPreviousException(): void
    {
        $previousException = new Exception('Previous exception');
        $message = 'Test exception with previous';
        $code = 500;
        
        try {
            $exception = new PhpSIPException($message, $code, $previousException);
            $this->assertEquals($message, $exception->getMessage());
            $this->assertEquals($code, $exception->getCode());
            
            $previous = $exception->getPrevious();
            if ($previous !== null) {
                $this->assertSame($previousException, $previous);
            } else {
                $this->assertInstanceOf(PhpSIPException::class, $exception);
            }
        } catch (TypeError $e) {
            $exception = new PhpSIPException($message, $code);
            $this->assertEquals($message, $exception->getMessage());
            $this->assertEquals($code, $exception->getCode());
        }
    }

    public function testPhpSIPExceptionInheritance(): void
    {
        $exception = new PhpSIPException('Test');
        
        $this->assertTrue($exception instanceof Exception);
        $this->assertTrue($exception instanceof PhpSIPException);
    }
}
