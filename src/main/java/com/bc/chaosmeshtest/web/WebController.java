package com.bc.chaosmeshtest.web;

import com.bc.chaosmeshtest.model.Product;
import com.bc.chaosmeshtest.repository.ProductRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import reactor.core.publisher.Flux;

@RequestMapping
public class WebController {
    private final ProductRepository productRepository;

    public WebController(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @GetMapping("/products")
    public Flux<Product> getProducts() {
        return productRepository.findAll();
    }
}
