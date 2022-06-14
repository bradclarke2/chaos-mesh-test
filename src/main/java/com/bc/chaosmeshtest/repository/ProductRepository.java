package com.bc.chaosmeshtest.repository;

import com.bc.chaosmeshtest.model.Product;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;

public interface ProductRepository extends ReactiveCrudRepository<Product, String> {

}
