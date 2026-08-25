class Unused {}

class UnusedCatchType {
    static function main() {
        try {
            throw "x";
        } catch (e:Unused) {
            Sys.println("unused");
        }
    }
}
