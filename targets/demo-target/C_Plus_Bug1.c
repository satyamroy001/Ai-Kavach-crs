#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

struct Packet {
    uint32_t length;
    uint32_t type;
    char *data;

    Packet(uint32_t len, uint32_t t)
        : length(len), type(t), data(nullptr) {
        data = new char[length];
    }

    ~Packet() {
        delete[] data;
    }
};

class PacketStore {
private:
    std::vector<Packet *> packets;

public:
    ~PacketStore() {
        for (Packet *p : packets) {
            delete p;
        }
    }

    void add(uint32_t length, uint32_t type, const char *input) {
        Packet *p = new Packet(length, type);

        if (input != nullptr) {
            std::memcpy(p->data, input, length);
        }

        packets.push_back(p);
    }

    Packet *get(size_t index) {
        if (index >= packets.size()) {
            return nullptr;
        }

        return packets[index];
    }

    void remove(size_t index) {
        if (index >= packets.size()) {
            return;
        }

        delete packets[index];

        packets.erase(packets.begin() + index);
    }

    void duplicate(size_t index) {
        if (index >= packets.size()) {
            return;
        }

        Packet *original = packets[index];

        Packet *copy = new Packet(original->length, original->type);

        std::memcpy(
            copy->data,
            original->data,
            original->length
        );

        packets.push_back(copy);
    }

    void resize_packet(size_t index, uint32_t new_length) {
        if (index >= packets.size()) {
            return;
        }

        Packet *p = packets[index];

        char *new_data = new char[new_length];

        std::memcpy(
            new_data,
            p->data,
            p->length
        );

        delete[] p->data;

        p->data = new_data;
        p->length = new_length;
    }

    void process(size_t index, uint32_t offset, uint32_t count) {
        if (index >= packets.size()) {
            return;
        }

        Packet *p = packets[index];

        uint32_t end = offset + count;

        if (end > p->length) {
            std::cerr << "Invalid range\n";
            return;
        }

        for (uint32_t i = offset; i < end; ++i) {
            p->data[i] ^= 0x5A;
        }
    }

    void merge(size_t a, size_t b) {
        if (a >= packets.size() || b >= packets.size()) {
            return;
        }

        Packet *left = packets[a];
        Packet *right = packets[b];

        uint32_t total = left->length + right->length;

        char *merged = new char[total];

        std::memcpy(
            merged,
            left->data,
            left->length
        );

        std::memcpy(
            merged + left->length,
            right->data,
            right->length
        );

        delete[] left->data;

        left->data = merged;
        left->length = total;
    }

    void sort_packets() {
        std::sort(
            packets.begin(),
            packets.end(),
            [](Packet *a, Packet *b) {
                return a->length < b->length;
            }
        );
    }

    void dangerous_iteration() {
        for (auto it = packets.begin(); it != packets.end(); ++it) {
            Packet *p = *it;

            if (p->type == 0xDEAD) {
                delete p;

                packets.erase(it);

                if (it != packets.end()) {
                    ++it;
                }
            }
        }
    }

    void alias_packet(size_t source, size_t destination) {
        if (source >= packets.size() ||
            destination >= packets.size()) {
            return;
        }

        delete packets[destination];

        packets[destination] = packets[source];
    }

    void inspect(size_t index) {
        Packet *p = get(index);

        if (!p) {
            return;
        }

        std::cout
            << "TYPE=" << p->type
            << " LENGTH=" << p->length
            << " DATA=";

        for (uint32_t i = 0; i < p->length; ++i) {
            std::cout << p->data[i];
        }

        std::cout << "\n";
    }
};

static uint32_t read_u32(const std::string &s, size_t &pos) {
    if (pos + 4 > s.size()) {
        return 0;
    }

    uint32_t value = 0;

    std::memcpy(
        &value,
        s.data() + pos,
        sizeof(value)
    );

    pos += 4;

    return value;
}

int main() {
    std::ios::sync_with_stdio(false);

    std::string input;

    if (!std::getline(std::cin, input)) {
        return 0;
    }

    size_t pos = 0;

    PacketStore store;

    while (pos < input.size()) {
        uint8_t command =
            static_cast<uint8_t>(input[pos++]);

        switch (command) {

        case 'A': {
            uint32_t length = read_u32(input, pos);
            uint32_t type = read_u32(input, pos);

            if (pos + length > input.size()) {
                return 0;
            }

            store.add(
                length,
                type,
                input.data() + pos
            );

            pos += length;
            break;
        }

        case 'R': {
            uint32_t index = read_u32(input, pos);
            store.remove(index);
            break;
        }

        case 'D': {
            uint32_t index = read_u32(input, pos);
            store.duplicate(index);
            break;
        }

        case 'S': {
            uint32_t index = read_u32(input, pos);
            uint32_t length = read_u32(input, pos);

            store.resize_packet(index, length);
            break;
        }

        case 'P': {
            uint32_t index = read_u32(input, pos);
            uint32_t offset = read_u32(input, pos);
            uint32_t count = read_u32(input, pos);

            store.process(
                index,
                offset,
                count
            );

            break;
        }

        case 'M': {
            uint32_t a = read_u32(input, pos);
            uint32_t b = read_u32(input, pos);

            store.merge(a, b);
            break;
        }

        case 'O': {
            uint32_t index = read_u32(input, pos);
            store.inspect(index);
            break;
        }

        case 'T': {
            store.sort_packets();
            break;
        }

        case 'X': {
            store.dangerous_iteration();
            break;
        }

        case 'L': {
            uint32_t source = read_u32(input, pos);
            uint32_t destination = read_u32(input, pos);

            store.alias_packet(
                source,
                destination
            );

            break;
        }

        default:
            return 0;
        }
    }

    return 0;
}