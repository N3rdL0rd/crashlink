class VirtualClosure {
    public static function main() {
        var myObject:Base = new Child();
        var func = myObject.sayHello;
        func();
    }
}

class Base {
    public function new() {}

    public function sayHello() {
        trace("Hello from Base");
    }
}

class Child extends Base {
    public function new() {
        super();
    }

    override public function sayHello() {
        trace("GREETINGS FROM CHILD!");
    }
}
