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

class VirtualClosure {
    public static function main() {
        // 1. Create an instance of the child class, but store it in a variable
        //    typed as the base class. This forces the compiler to consider
        //    virtual dispatch.
        var myObject:Base = new Child();

        // 2. THIS IS THE LINE THAT GENERATES OVirtualClosure.
        //    We are not calling the method directly. Instead, we are getting a
        //    reference to it, creating a closure. Because the compiler knows
        //    'sayHello' can be overridden, it must use a virtual lookup.
        var func = myObject.sayHello;

        // 3. Call the created closure.
        func(); // This will print "GREETINGS FROM CHILD!"
    }
}