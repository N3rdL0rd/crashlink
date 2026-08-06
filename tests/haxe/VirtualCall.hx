class Animal {
    public function new() {}

    public function speak():String {
        return "...";
    }

    public function describe():String {
        return "animal says " + speak();
    }
}

class Dog extends Animal {
    public function new() {
        super();
    }

    override function speak():String {
        return "woof";
    }
}

class VirtualCall {
    static function main() {
        var a:Animal = new Dog();
        Sys.println(a.describe());
        Sys.println(a.speak());
    }
}
