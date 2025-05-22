import * as THREE from 'https://unpkg.com/three@0.149.0/build/three.module.js';

// Initialize Three.js scene
let scene, camera, renderer, particles;

function init() {
    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    
    renderer = new THREE.WebGLRenderer({ 
        alpha: true,
        antialias: true 
    });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);
    
    document.getElementById('three-container').appendChild(renderer.domElement);
    
    // Create particles with improved aesthetics
    const geometry = new THREE.BufferGeometry();
    const vertices = [];
    const colors = [];
    const sizes = [];
    
    const color = new THREE.Color();
    
    for (let i = 0; i < 6000; i++) {
        vertices.push(
            Math.random() * 2000 - 1000,
            Math.random() * 2000 - 1000,
            Math.random() * 2000 - 1000
        );
        
        // Random size for each particle
        sizes.push(Math.random() * 3 + 2);
        
        // Gradient color from primary to secondary
        const mixRatio = Math.random();
        color.setHSL(0.4 + Math.random() * 0.1, 0.8, 0.6);
        colors.push(color.r, color.g, color.b);
    }
    
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
    geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
    geometry.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));
    
    const material = new THREE.PointsMaterial({
        size: 4,
        sizeAttenuation: true,
        vertexColors: true,
        transparent: true,
        opacity: 0.8,
        blending: THREE.AdditiveBlending
    });
    
    particles = new THREE.Points(geometry, material);
    scene.add(particles);
    
    camera.position.z = 1000;
    
    // Add mouse interaction
    document.addEventListener('mousemove', onMouseMove);
}

let mouseX = 0;
let mouseY = 0;
let targetRotationX = 0;
let targetRotationY = 0;

function onMouseMove(event) {
    mouseX = (event.clientX - window.innerWidth / 2) / 100;
    mouseY = (event.clientY - window.innerHeight / 2) / 100;
}

function animate() {
    requestAnimationFrame(animate);
    
    // Smooth rotation following mouse
    targetRotationX += (mouseY - targetRotationX) * 0.05;
    targetRotationY += (mouseX - targetRotationY) * 0.05;
    
    particles.rotation.x = targetRotationX * 0.3;
    particles.rotation.y = targetRotationY * 0.3;
    
    // Gentle wave motion
    const positions = particles.geometry.attributes.position.array;
    const time = Date.now() * 0.0001;
    
    for(let i = 0; i < positions.length; i += 3) {
        positions[i + 1] += Math.sin(time + positions[i] * 0.001) * 0.1;
    }
    particles.geometry.attributes.position.needsUpdate = true;
    
    renderer.render(scene, camera);
}

function onWindowResize() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
}

window.addEventListener('resize', onWindowResize, false);

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const container = document.createElement('div');
    container.id = 'three-container';
    document.body.appendChild(container);
    
    init();
    animate();
});
