#pragma once

#include "../../include/common.h"

#include <bpf/bpf.h>

#include <cstddef>
#include <utility>
#include <vector>

template <typename T>
T makeEmptyEntry() {
    T entry{};
    entry.direction = 255;
    entry.enabled = 0;
    return entry;
}

template <typename T>
class AclTable {
public:
    bool initialize(int fd) {
        fd_ = fd;

        fetch();

        return true;
    }

    bool insert(const T& rule, size_t index) {
        if (index > entries_.size() || entries_.size() >= MAX_ENTRIES)
            return false;

        std::vector<T> backup = entries_;
        entries_.insert(entries_.begin() + index, rule);

        bool ok = true;

        for (size_t i = index; i < entries_.size() && ok; ++i)
              ok = write(static_cast<u32>(i), entries_[i]);
        if (!ok) {
            entries_ = std::move(backup);
            rewriteAll();
            return false;
        }

        return true;
    }

    bool remove(size_t index) {
        if (index >= entries_.size())
            return false;

        std::vector<T> backup = entries_;
        entries_.erase(entries_.begin() + index);

        bool ok = true;

        for (size_t i = index; i < entries_.size() && ok; ++i)
            ok = write(static_cast<u32>(i), entries_[i]);

        if (ok)
            ok = write(static_cast<u32>(entries_.size()), makeEmptyEntry<T>());

        if (!ok) {
            entries_ = std::move(backup);
            rewriteAll();
            return false;
        }

        return true;
    }

    bool update(const T& rule, size_t index) {
        if (index >= entries_.size())
            return false;

        if (!write(static_cast<u32>(index), rule))
            return false;

        entries_[index] = rule;
        return true;
    }

    size_t size() const noexcept {
        return entries_.size();
    }

    const std::vector<T>& entries() const noexcept {
        return entries_;
    }

    bool fetch() {
        if (fd_ < 0)
            return false;

        std::vector<T> fresh;
        fresh.reserve(entries_.size());

        bool ok = true;

        for (u32 i = 0; i < MAX_ENTRIES; ++i) {
            T value{};
            if (!read(i, value)) {
                ok = false;
                continue;
            }

            if (value.enabled)
                fresh.push_back(value);
        }

        entries_ = std::move(fresh);
        return ok;
    }
private:
    int fd_{-1};
    std::vector<T> entries_;

    bool write(u32 key, const T& value) const {
        return bpf_map_update_elem(fd_, &key, &value, BPF_ANY) == 0;
    }
    bool read(u32 key, T& value) const {
         return bpf_map_lookup_elem(fd_, &key, &value) == 0;
     }
    void rewriteAll() {
        const T empty = makeEmptyEntry<T>();

        for (u32 i = 0; i < MAX_ENTRIES; ++i) {
            if (i < entries_.size())
                write(i, entries_[i]);
            else
                write(i, empty);
        }
    }
};
