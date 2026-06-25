enum Status {
    Ready;
    Busy;
    Failed;
}
class EnumGlobalOrderCase {
    static function main() {
        trace(Failed);
        trace(Busy);
        trace(Ready);
    }
}
